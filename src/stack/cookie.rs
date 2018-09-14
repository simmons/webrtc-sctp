//! SCTP cookies are part of the 4-way handshake, and provide a means for the server to avoid
//! storing state after receiving an INIT from a peer, thus avoiding certain types of denial of
//! service attacks.

use blake2::crypto_mac::Mac;
use blake2::Blake2b;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::{self, RngCore};
use std::io;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use time;

use super::settings::DEFAULT_SCTP_PARAMETERS;
use packet::TSN;
use util;

#[derive(Clone)]
struct CookieTime {
    epoch: u64,
}

/// The Secret struct contains a secret key to be used for generating HMACs, and provides functions
/// for basic MAC generation and verification.  A Secret is cloneable and maintains a shared inner
/// state so all holders of a cloned Secret will access the same key.  The secret may (and should)
/// be periodically regenerated via regenerate().  The Secret will store a copy of the previous key
/// which may be used for verifying cookies with timestamps indicating they were produced prior to
/// the generation of the current key.  Therefore, cookies in transit during a regeneration may
/// still be verified (until the next regeneration, of course).
#[derive(Clone)]
pub struct Secret {
    inner: Arc<Mutex<SecretInner>>,
}

struct SecretInner {
    key: [u8; BLAKE2B_MAC_SIZE],
    previous_key: [u8; BLAKE2B_MAC_SIZE],
    generation_time: u64,
    expiration_time: u64,
    has_previous: bool,
}

const BLAKE2B_MAC_SIZE: usize = 64;

impl Secret {
    pub fn new() -> Secret {
        let mut key = [0u8; BLAKE2B_MAC_SIZE];
        let previous_key = [0u8; BLAKE2B_MAC_SIZE];
        rand::thread_rng().fill_bytes(&mut key);

        const NANOSECONDS_IN_MILLISECOND: u64 = 1000000;
        let generation_time = time::precise_time_ns();
        let expiration_time = generation_time
            + DEFAULT_SCTP_PARAMETERS.secret_key_regeneration_interval * NANOSECONDS_IN_MILLISECOND;

        Secret {
            inner: Arc::new(Mutex::new(SecretInner {
                key,
                previous_key,
                generation_time,
                expiration_time,
                has_previous: false,
            })),
        }
    }

    fn regenerate(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.previous_key = inner.key;
        inner.has_previous = true;
        rand::thread_rng().fill_bytes(&mut inner.key);
        inner.generation_time = time::precise_time_ns();
    }

    fn regenerate_if_needed(&self) {
        let inner = self.inner.lock().unwrap();
        if time::precise_time_ns() >= inner.expiration_time {
            drop(inner);
            self.regenerate();
        }
    }

    fn mac(&self, buffer: &[u8]) -> [u8; BLAKE2B_MAC_SIZE] {
        self.regenerate_if_needed();

        let inner = self.inner.lock().unwrap();
        let mut hasher = Blake2b::new(&inner.key).unwrap();
        hasher.input(buffer);
        let mut mac = [0u8; BLAKE2B_MAC_SIZE];
        let code = hasher.result().code();
        mac.clone_from_slice(code.as_slice());
        mac
    }

    fn verify(&self, buffer: &[u8], mac: &[u8], timestamp: u64) -> io::Result<()> {
        self.regenerate_if_needed();

        if mac.len() != BLAKE2B_MAC_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad MAC"));
        }

        let inner = self.inner.lock().unwrap();
        let key = if timestamp < inner.generation_time {
            &inner.previous_key
        } else {
            &inner.key
        };
        let mut hasher = Blake2b::new(key).unwrap();
        hasher.input(buffer);
        match hasher.verify(mac) {
            Ok(_) => Ok(()),
            Err(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "bad MAC")),
        }
    }
}

use std::fmt;

#[allow(dead_code)]
pub struct Hex<'a>(&'a [u8]);
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        writeln!(f, "Secret: generation_time={} key:", inner.generation_time)?;
        util::hexdump(f, "\t", &inner.key)?;
        writeln!(f, "")?;
        if inner.has_previous {
            writeln!(f, "\tprevious_key:")?;
            util::hexdump(f, "\t", &inner.previous_key)?;
        } else {
            write!(f, "\tprevious_key: None")?;
        };
        Ok(())
    }
}

#[derive(Debug)]
pub struct Cookie {
    pub timestamp: u64,
    pub local_port: u16,
    pub sctp_peer: SocketAddr,
    pub llp_peer: SocketAddr,
    pub local_verification_tag: u32,
    pub peer_verification_tag: u32,
    pub initial_send_tsn: TSN,
    pub initial_recv_tsn: TSN,
    pub peer_rwnd: u32,
    pub peer_num_outbound_streams: u16,
    pub peer_num_inbound_streams: u16,
}

const TAG_IPV4: u8 = 0x00;
const TAG_IPV6: u8 = 0x01;

impl Cookie {
    pub fn new(
        local_port: u16,
        sctp_peer: SocketAddr,
        llp_peer: SocketAddr,
        local_verification_tag: u32,
        peer_verification_tag: u32,
        initial_send_tsn: TSN,
        initial_recv_tsn: TSN,
        peer_rwnd: u32,
        peer_num_outbound_streams: u16,
        peer_num_inbound_streams: u16,
    ) -> Cookie {
        Cookie {
            timestamp: time::precise_time_ns(),
            local_port,
            sctp_peer,
            llp_peer,
            local_verification_tag,
            peer_verification_tag,
            initial_send_tsn,
            initial_recv_tsn,
            peer_rwnd,
            peer_num_outbound_streams,
            peer_num_inbound_streams,
        }
    }

    fn serialize_socketaddr(cursor: &mut Cursor<Vec<u8>>, addr: &SocketAddr) -> io::Result<()> {
        use self::IpAddr::*;
        match addr.ip() {
            V4(ip) => {
                cursor.write_all(&[TAG_IPV4])?;
                cursor.write_all(&[0; 12])?;
                cursor.write_all(&ip.octets())?;
            }
            V6(ip) => {
                cursor.write_all(&[TAG_IPV6])?;
                cursor.write_all(&ip.octets())?;
            }
        }
        cursor.write_u16::<BigEndian>(addr.port()).unwrap();
        Ok(())
    }

    fn deserialize_sockaddr(cursor: &mut Cursor<Vec<u8>>) -> io::Result<SocketAddr> {
        let mut discriminator = [0u8; 1];
        cursor.read_exact(&mut discriminator)?;
        let ip: IpAddr = match discriminator[0] {
            TAG_IPV4 => {
                let mut padding = [0u8; 12];
                let mut bytes = [0u8; 4];
                cursor.read_exact(&mut padding)?;
                cursor.read_exact(&mut bytes)?;
                Ipv4Addr::from(bytes).into()
            }
            TAG_IPV6 => {
                let mut bytes = [0u8; 16];
                cursor.read_exact(&mut bytes)?;
                Ipv6Addr::from(bytes).into()
            }
            _ => return Err(io::Error::new(io::ErrorKind::Other, "ip deserialization")),
        };
        let port = cursor.read_u16::<BigEndian>()?;
        Ok(SocketAddr::new(ip, port))
    }

    pub fn serialize(&self, secret: &Secret) -> io::Result<Vec<u8>> {
        let mut cursor = Cursor::new(Vec::new());
        cursor.write_all(&[0; BLAKE2B_MAC_SIZE])?; // placeholder
        cursor.write_u64::<BigEndian>(self.timestamp)?;
        cursor.write_u16::<BigEndian>(self.local_port)?;
        Self::serialize_socketaddr(&mut cursor, &self.sctp_peer)?;
        Self::serialize_socketaddr(&mut cursor, &self.llp_peer)?;
        cursor.write_u32::<BigEndian>(self.local_verification_tag)?;
        cursor.write_u32::<BigEndian>(self.peer_verification_tag)?;
        cursor.write_u32::<BigEndian>(self.initial_send_tsn.into())?;
        cursor.write_u32::<BigEndian>(self.initial_recv_tsn.into())?;
        cursor.write_u32::<BigEndian>(self.peer_rwnd)?;
        cursor.write_u16::<BigEndian>(self.peer_num_outbound_streams)?;
        cursor.write_u16::<BigEndian>(self.peer_num_inbound_streams)?;
        let mut serialization = cursor.into_inner();

        // Write the MAC
        let mac = secret.mac(&serialization[BLAKE2B_MAC_SIZE..]);
        &mut serialization[0..BLAKE2B_MAC_SIZE].clone_from_slice(&mac);

        Ok(serialization)
    }

    pub fn deserialize(secret: &Secret, buffer: &[u8]) -> io::Result<Cookie> {
        let mut cursor = Cursor::new(buffer.to_owned());

        let mut mac: Vec<u8> = vec![0; BLAKE2B_MAC_SIZE];
        cursor.read_exact(&mut mac)?;
        let timestamp = cursor.read_u64::<BigEndian>()?;

        secret.verify(&buffer[BLAKE2B_MAC_SIZE..], &mac, timestamp)?;

        let local_port = cursor.read_u16::<BigEndian>()?;
        let sctp_peer = Self::deserialize_sockaddr(&mut cursor)?;
        let llp_peer = Self::deserialize_sockaddr(&mut cursor)?;
        let local_verification_tag = cursor.read_u32::<BigEndian>()?;
        let peer_verification_tag = cursor.read_u32::<BigEndian>()?;
        let initial_send_tsn: TSN = cursor.read_u32::<BigEndian>()?.into();
        let initial_recv_tsn: TSN = cursor.read_u32::<BigEndian>()?.into();
        let peer_rwnd: u32 = cursor.read_u32::<BigEndian>()?;
        let peer_num_outbound_streams: u16 = cursor.read_u16::<BigEndian>()?;
        let peer_num_inbound_streams: u16 = cursor.read_u16::<BigEndian>()?;

        Ok(Cookie {
            timestamp,
            local_port,
            sctp_peer,
            llp_peer,
            local_verification_tag,
            peer_verification_tag,
            initial_send_tsn,
            initial_recv_tsn,
            peer_rwnd,
            peer_num_outbound_streams,
            peer_num_inbound_streams,
        })
    }
}
