//! SCTP packet parsing and synthesis

#[macro_use]
mod parse_utils;
mod checksum;
pub mod chunk;
pub mod error_cause;
pub mod parameter;
mod writer;

use std::fmt;

use nom::{be_u16, be_u32, IResult};

use self::chunk::*;
use self::writer::{Result as WriterResult, Writer};
use error::SctpError;
use util::serial::Serial;

pub type TSN = Serial<u32>;
pub type SSN = Serial<u16>;

pub struct SctpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub verification_tag: u32,
}

pub struct SctpPacket {
    pub header: SctpHeader,
    pub chunks: Vec<Chunk>,
}

impl fmt::Display for SctpPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(
            f,
            "src_port: {} dst_port: {} verification_tag: 0x{:x} chunks: {}",
            self.header.source_port,
            self.header.destination_port,
            self.header.verification_tag,
            self.chunks.len()
        ));
        for chunk in &self.chunks {
            try!(writeln!(f, "    {:?}", chunk));
        }
        Ok(())
    }
}

impl fmt::Debug for SctpPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self as &fmt::Display).fmt(f)
    }
}

impl SctpPacket {
    // TODO: inefficient... this allocates memory for every packet.
    // Someday we should instead maintain an arena of fixed-size buffers.
    pub fn write(&self) -> WriterResult<Vec<u8>> {
        let mut writer = writer::WriterOwned::new();
        writer.write_header(&self.header)?;
        for chunk in &self.chunks {
            writer.write_chunk(chunk)?;
        }
        let mut buffer = writer.to_owned();
        checksum::write(&mut buffer);
        Ok(buffer)
    }
}

fn sctp_packet<'a>(input: &'a [u8]) -> IResult<&'a [u8], SctpPacket> {
    do_parse!(
        input,
        source_port:        be_u16  >>
        destination_port:   be_u16  >>
        verification_tag:   be_u32  >>
                            be_u32  >> // checksum
        chunks:             many0!(parse_chunk) >> ({
            SctpPacket {
                header: SctpHeader {
                    source_port: source_port,
                    destination_port: destination_port,
                    verification_tag: verification_tag,
                },
                chunks: chunks,
            }
        })
    )
}

const MINIMUM_PACKET_SIZE: usize = 12;

/// Parse the provided byte slice as an SCTP packet.
pub fn parse(packet_buffer: &[u8]) -> Result<SctpPacket, SctpError> {
    if packet_buffer.len() < MINIMUM_PACKET_SIZE {
        return Err(SctpError::InvalidPacket);
    }

    if !::packet::checksum::verify(packet_buffer) {
        return Err(SctpError::BadChecksum);
    }

    let packet = match sctp_packet(packet_buffer) {
        Ok((_, o)) => o,
        Err(_) => {
            return Err(SctpError::InvalidPacket);
        }
    };

    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::parameter::Parameter;
    use super::*;

    // Packet 1: INIT
    const PACKET_1_BYTES: &[u8] = &[
        0xbf, 0x44, 0x07, 0xe4, 0x00, 0x00, 0x00, 0x00, // 0000: .D......
        0x1e, 0x82, 0x80, 0x41, 0x01, 0x00, 0x00, 0x80, // 0008: ...A....
        0x63, 0xd6, 0x74, 0x5f, 0x00, 0x01, 0xa0, 0x00, // 0010: c.t_....
        0x00, 0x0a, 0xff, 0xff, 0x0c, 0x44, 0x7d, 0x28, // 0018: .....D}(
        0x00, 0x05, 0x00, 0x08, 0x7f, 0x00, 0x00, 0x01, // 0020: ........
        0x00, 0x06, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, // 0028: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0030: ........
        0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00, 0x08, // 0038: ........
        0x0a, 0x00, 0x02, 0x0f, 0x00, 0x06, 0x00, 0x14, // 0040: ........
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0048: ........
        0x0a, 0x00, 0x27, 0xff, 0xfe, 0x19, 0xf7, 0x37, // 0050: ..'....7
        0x00, 0x05, 0x00, 0x08, 0x0a, 0x0a, 0x0a, 0x65, // 0058: .......e
        0x00, 0x06, 0x00, 0x14, 0xfe, 0x80, 0x00, 0x00, // 0060: ........
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x27, 0xff, // 0068: ......'.
        0xfe, 0xbe, 0x6b, 0x99, 0x00, 0x05, 0x00, 0x08, // 0070: ..k.....
        0xac, 0x11, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x08, // 0078: ........
        0x00, 0x06, 0x00, 0x05, 0x80, 0x00, 0x00, 0x04, // 0080: ........
        0xc0, 0x00, 0x00, 0x04, // 0088: ....
    ];

    fn expected_init_chunk() -> Chunk {
        Chunk::Init(InitChunk {
            initiate_tag: 1674998879,
            a_rwnd: 106496,
            num_outbound_streams: 10,
            num_inbound_streams: 65535,
            initial_tsn: 205815080,
            parameters: vec![
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[127, 0, 0, 1])),
                Parameter::IPv6Address(parameter::IPv6Address::from_bytes(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ])),
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[10, 0, 2, 15])),
                Parameter::IPv6Address(parameter::IPv6Address::from_bytes(&[
                    // fe80:0:0:0:a00:27ff:fe19:f737
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x27, 0xff, 0xfe,
                    0x19, 0xf7, 0x37,
                ])),
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[10, 10, 10, 101])),
                Parameter::IPv6Address(parameter::IPv6Address::from_bytes(&[
                    // fe80:0:0:0:a00:27ff:febe:6b99
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x27, 0xff, 0xfe,
                    0xbe, 0x6b, 0x99,
                ])),
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[172, 17, 0, 1])),
                Parameter::SupportedAddressTypes(vec![
                    parameter::IPV6ADDRESS_TYPE,
                    parameter::IPV4ADDRESS_TYPE,
                ]),
                Parameter::ECNCapable,
                Parameter::ForwardTSNSupported,
            ],
        })
    }

    #[test]
    fn test_packet_init() {
        assert!(::packet::checksum::verify(PACKET_1_BYTES));
        let (remainder, packet) = sctp_packet(PACKET_1_BYTES).unwrap();
        assert_eq!(remainder.len(), 0);
        assert_eq!(packet.header.source_port, 48964);
        assert_eq!(packet.header.destination_port, 2020);
        assert_eq!(packet.header.verification_tag, 0x0);
        assert_eq!(packet.chunks.len(), 1);
        assert_eq!(packet.chunks[0], expected_init_chunk());
    }

    // Packet 2: COOKIE ACK and SACK
    const PACKET_2_BYTES: &[u8] = &[
        0x07, 0xe4, 0x07, 0xe4, 0xd9, 0xc9, 0x88, 0x99, // 0000: ........
        0x09, 0x06, 0x9c, 0x8b, 0x0b, 0x00, 0x00, 0x04, // 0008: ........
        0x03, 0x00, 0x00, 0x10, 0x17, 0xeb, 0xe3, 0x26, // 0010: .......&
        0x00, 0x01, 0x9f, 0xef, 0x00, 0x00, 0x00, 0x00, // 0018: ........
    ];

    fn expected_cookie_ack() -> Chunk {
        Chunk::CookieAck(CookieAckChunk {})
    }

    fn expected_sack() -> Chunk {
        Chunk::Sack(SackChunk {
            cumulative_tsn_ack: TSN::new(401335078),
            a_rwnd: 106479,
            gap_ack_blocks: vec![],
            duplicate_tsns: vec![],
        })
    }

    #[test]
    fn test_packet_cookie_ack_and_sack() {
        assert!(::packet::checksum::verify(PACKET_2_BYTES));
        let (remainder, packet) = sctp_packet(PACKET_2_BYTES).unwrap();
        assert_eq!(remainder.len(), 0);
        assert_eq!(packet.header.source_port, 2020);
        assert_eq!(packet.header.destination_port, 2020);
        assert_eq!(packet.header.verification_tag, 0xd9c98899);
        assert_eq!(packet.chunks.len(), 2);
        assert_eq!(packet.chunks[0], expected_cookie_ack());
        assert_eq!(packet.chunks[1], expected_sack());
    }
}
