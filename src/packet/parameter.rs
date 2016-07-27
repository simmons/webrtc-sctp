//! SCTP parameter parsing and synthesis

use std::fmt;

use nom::simple_errors::Context;
use nom::{be_u16, be_u32, rest, Err, ErrorKind, IResult};

use packet::writer::{Result as WriterResult, Writer};
use util::{hexdump, shorthash};

// TODO: Padding of the last parameter is not included in the chunk length.
// Also, padding should be optional. (?)
// See: https://tools.ietf.org/id/draft-ietf-tsvwg-sctpimpguide-01.txt
//
// "The above text makes clear that the padding of the last parameter is
// not included in the Chunk Length field. It also clarifies that the
// padding of parameters that are not the last one must be counted in
// the Chunk Length field."

// Parameter types
// http://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml
const HEARTBEAT_INFO_TYPE: u16 = 1;
pub const IPV4ADDRESS_TYPE: u16 = 5;
pub const IPV6ADDRESS_TYPE: u16 = 6;
const STATE_COOKIE_TYPE: u16 = 7;
const UNRECOGNIZED_PARAMETER_TYPE: u16 = 8;
const COOKIE_PRESERVATIVE_TYPE: u16 = 9;
const HOST_NAME_ADDRESS_TYPE: u16 = 11;
const SUPPORTED_ADDRESS_TYPES_TYPE: u16 = 12;
const ECNCAPABLE_TYPE: u16 = 32768;
const FORWARD_TSN_SUPPORTED_TYPE: u16 = 49152;

#[derive(Clone, Debug, PartialEq)]
pub enum Parameter {
    HeartbeatInfo(Vec<u8>),
    IPv4Address(IPv4Address),
    IPv6Address(IPv6Address),
    StateCookie(Vec<u8>),
    UnrecognizedParameter(Vec<u8>),
    CookiePreservative(u32),
    HostNameAddress(String),
    SupportedAddressTypes(Vec<u16>),
    ECNCapable,
    ForwardTSNSupported,
    Unknown(u16, Vec<u8>),
}

const IPV4ADDRESS_SIZE: usize = 4;
const IPV6ADDRESS_SIZE: usize = 16;

#[derive(Clone, PartialEq)]
pub struct IPv4Address {
    pub value: u32,
}
impl IPv4Address {
    pub fn from_bytes(bytes: &[u8; 4]) -> IPv4Address {
        IPv4Address {
            value: ((bytes[0] as u32) << 24)
                | ((bytes[1] as u32) << 16)
                | ((bytes[2] as u32) << 8)
                | ((bytes[3] as u32) << 0),
        }
    }
}
impl fmt::Display for IPv4Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            (self.value >> 24) & 0xFF,
            (self.value >> 16) & 0xFF,
            (self.value >> 8) & 0xFF,
            (self.value >> 0) & 0xFF
        )
    }
}
impl fmt::Debug for IPv4Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self as &fmt::Display).fmt(f)
    }
}

#[derive(Clone, PartialEq)]
pub struct IPv6Address {
    pub value: [u8; 16],
}
impl IPv6Address {
    pub fn from_bytes(bytes: &[u8; 16]) -> IPv6Address {
        IPv6Address { value: *bytes }
    }
}
impl fmt::Display for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            (self.value[0] as u16) << 8 | self.value[1] as u16,
            (self.value[2] as u16) << 8 | self.value[3] as u16,
            (self.value[4] as u16) << 8 | self.value[5] as u16,
            (self.value[6] as u16) << 8 | self.value[7] as u16,
            (self.value[8] as u16) << 8 | self.value[9] as u16,
            (self.value[10] as u16) << 8 | self.value[11] as u16,
            (self.value[12] as u16) << 8 | self.value[13] as u16,
            (self.value[14] as u16) << 8 | self.value[15] as u16
        )
    }
}
impl fmt::Debug for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self as &fmt::Display).fmt(f)
    }
}

// Display a parameter
impl fmt::Display for Parameter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Parameter::HeartbeatInfo(ref data) => {
                try!(writeln!(f, "HeartbeatInfo"));
                hexdump(f, "\t\t", data.as_slice())
            }
            Parameter::IPv4Address(ref addr) => write!(f, "IPv4Address {}", addr),
            Parameter::IPv6Address(ref addr) => write!(f, "IPv6Address {}", addr),
            Parameter::StateCookie(ref data) => {
                // try!(writeln!(f, "StateCookie"));
                // hexdump(f, "\t\t", data.as_slice())
                write!(f, "StateCookie {} ({} bytes)", shorthash(data), data.len())
            }
            Parameter::UnrecognizedParameter(ref data) => write!(f, "Unrecognized {:?}", data),
            Parameter::CookiePreservative(ref data) => write!(f, "CookiePreservative {:?}", data),
            Parameter::HostNameAddress(ref hostname) => {
                write!(f, "HostNameAddress \"{}\"", hostname)
            }
            Parameter::SupportedAddressTypes(ref types) => {
                write!(f, "SupportedAddressTypes {:?}", types)
            }
            Parameter::ECNCapable => write!(f, "ECNCapable"),
            Parameter::ForwardTSNSupported => write!(f, "ForwardTSNSupported"),
            Parameter::Unknown(ptype, ref data) => {
                try!(writeln!(f, "Unknown{{type: {} (0x{:#04x})}}", ptype, ptype));
                hexdump(f, "\t", data.as_slice())
            }
        }
    }
}

// HeartbeatInfo Parameter

named!(heartbeatinfo_parameter<&[u8], Parameter>, do_parse!(
    data:                   rest >>
    ( Parameter::HeartbeatInfo(data.to_vec()) )
));

// IPv4Address Parameter

named!(ipv4address_parameter<&[u8], Parameter>, do_parse!(
    data: take!(IPV4ADDRESS_SIZE) >>
    (Parameter::IPv4Address(
        IPv4Address::from_bytes(&[ data[0], data[1], data[2], data[3] ])
    ))
));

// IPv6Address Parameter

named!(ipv6address_parameter<&[u8], Parameter>, do_parse!(
    data: take!(IPV6ADDRESS_SIZE) >>
    (
        Parameter::IPv6Address(
            IPv6Address::from_bytes(
                &[
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                    data[8], data[9], data[10], data[11],
                    data[12], data[13], data[14], data[15]
                ]
            )
        )
    )
));

// StateCookie Parameter

named!(statecookie_parameter<&[u8], Parameter>, do_parse!(
    // Type 17 is for StateCookie; that's good enough for me.
    data: rest >>
    ( Parameter::StateCookie(data.to_vec()) )
));

// UnrecognizedParameter Parameter

named!(unrecognizedparameter_parameter<&[u8], Parameter>, do_parse!(
    data: rest >>
    ( Parameter::UnrecognizedParameter(data.to_vec()) )
));

// CookiePreservative Parameter

named!(cookiepreservative_parameter<&[u8], Parameter>, do_parse!(
    lifespan_increment: be_u32 >>
    ( Parameter::CookiePreservative(lifespan_increment) )
));

// HostNameAddress Parameter

const HOSTNAME_MIN: usize = 1;
const HOSTNAME_MAX: usize = 256;

fn parse_hostname(input: &[u8]) -> IResult<&[u8], String> {
    let length = input.len();
    if length < (HOSTNAME_MIN + 1) || length > (HOSTNAME_MAX + 1) {
        // TODO: BAD_HOSTNAME?
        return Err(Err::Error(Context::Code(input, ErrorKind::Custom(0))));
    }
    if length > input.len() {
        // TODO: UNDERRUN
        return Err(Err::Error(Context::Code(input, ErrorKind::Custom(0))));
    }
    if input[length - 1] != 0 {
        // Final octet must be a null terminator
        return Err(Err::Error(Context::Code(input, ErrorKind::Custom(0))));
    }
    let mut s: String = String::with_capacity(length - 1);
    for octet in &input[..(length - 1)] {
        s.push(*octet as char);
    }
    Ok((&input[length..], s))
}

named!(hostnameaddress_parameter<&[u8], Parameter>, do_parse!(
    hostname:               call!(parse_hostname) >>
    ( Parameter::HostNameAddress(hostname) )
));

// SupportedAddressTypes Parameter

named!(supportedaddresstypes_parameter<&[u8], Parameter>, do_parse!(
    types:                  many0!(complete!(be_u16)) >>
    ( Parameter::SupportedAddressTypes(types) )
));

// ECNCapable Parameter

named!(ecncapable_parameter<&[u8], Parameter>, do_parse!(
    ( Parameter::ECNCapable )
));

// ForwardTSNSupported Parameter

named!(forwardtsnsupported_parameter<&[u8], Parameter>, do_parse!(
    ( Parameter::ForwardTSNSupported )
));

#[inline]
fn parameter_dispatch(tag: u16, value: &[u8]) -> IResult<&[u8], Parameter> {
    match tag {
        HEARTBEAT_INFO_TYPE => heartbeatinfo_parameter(value),
        IPV4ADDRESS_TYPE => ipv4address_parameter(value),
        IPV6ADDRESS_TYPE => ipv6address_parameter(value),
        STATE_COOKIE_TYPE => statecookie_parameter(value),
        UNRECOGNIZED_PARAMETER_TYPE => unrecognizedparameter_parameter(value),
        COOKIE_PRESERVATIVE_TYPE => cookiepreservative_parameter(value),
        HOST_NAME_ADDRESS_TYPE => hostnameaddress_parameter(value),
        SUPPORTED_ADDRESS_TYPES_TYPE => supportedaddresstypes_parameter(value),
        ECNCAPABLE_TYPE => ecncapable_parameter(value),
        FORWARD_TSN_SUPPORTED_TYPE => forwardtsnsupported_parameter(value),
        _ => Ok((&value[0..0], Parameter::Unknown(tag, value.to_owned()))),
    }
}

named!(pub parse_parameter<&[u8], Parameter>, do_parse!(
    parameter:  parse_tlv!(parameter_dispatch) >> ( parameter )
));

pub fn write_parameter(writer: &mut Writer, parameter: &Parameter) -> WriterResult<()> {
    match parameter {
        &Parameter::HeartbeatInfo(ref v) => {
            writer.open_tlv(HEARTBEAT_INFO_TYPE)?;
            writer.write_bytes(v)?;
            writer.close_tlv()?;
        }
        &Parameter::IPv4Address(ref addr) => {
            writer.open_tlv(IPV4ADDRESS_TYPE)?;
            writer.write_be32(addr.value)?;
            writer.close_tlv()?;
        }
        &Parameter::IPv6Address(ref addr) => {
            writer.open_tlv(IPV6ADDRESS_TYPE)?;
            writer.write_bytes(&addr.value)?;
            writer.close_tlv()?;
        }
        &Parameter::StateCookie(ref v) => {
            writer.open_tlv(STATE_COOKIE_TYPE)?;
            writer.write_bytes(v)?;
            writer.close_tlv()?;
        }
        &Parameter::UnrecognizedParameter(ref v) => {
            writer.open_tlv(UNRECOGNIZED_PARAMETER_TYPE)?;
            writer.write_bytes(v)?;
            writer.close_tlv()?;
        }
        &Parameter::CookiePreservative(v) => {
            writer.open_tlv(COOKIE_PRESERVATIVE_TYPE)?;
            writer.write_be32(v)?;
            writer.close_tlv()?;
        }
        &Parameter::HostNameAddress(ref name) => {
            writer.open_tlv(HOST_NAME_ADDRESS_TYPE)?;
            writer.write_bytes(name.as_bytes())?;
            writer.write_be8(0)?; // A null terminator is required
            writer.close_tlv()?;
        }
        &Parameter::SupportedAddressTypes(ref types) => {
            writer.open_tlv(SUPPORTED_ADDRESS_TYPES_TYPE)?;
            for t in types {
                writer.write_be16(*t)?;
            }
            writer.close_tlv()?;
        }
        &Parameter::ECNCapable => {
            writer.open_tlv(ECNCAPABLE_TYPE)?;
            writer.close_tlv()?;
        }
        &Parameter::ForwardTSNSupported => {
            writer.open_tlv(FORWARD_TSN_SUPPORTED_TYPE)?;
            writer.close_tlv()?;
        }
        &Parameter::Unknown(ptype, ref v) => {
            writer.open_tlv(ptype)?;
            writer.write_bytes(v)?;
            writer.close_tlv()?;
        }
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::writer::*;
    use util::tests::*;

    /// How many trailing bytes cases should we test?
    const MAX_TRAILING_BYTES: usize = 5;

    /// Serialize a parameter to a byte vector.
    fn serialize(parameter: &Parameter) -> Vec<u8> {
        let mut writer = WriterOwned::new();
        write_parameter(&mut writer, parameter).unwrap();
        writer.to_owned()
    }

    /// Perform basic parameter serialization and deserialization tests
    fn test_parameter(parameter: Parameter, expected_bytes: &[u8]) {
        // Test serialize
        let buffer = serialize(&parameter);
        assert_eq!(buffer, expected_bytes);

        // Test parsing
        let (remainder, parsed_parameter) = parse_parameter(&buffer).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(&parsed_parameter, &parameter);

        // Test serialization-deserialization with variable number of trailing bytes.
        test_parameter_serdes(&parameter);
    }

    /// Test serialization and deserialization of a particular parameter with
    /// a variable number of trailing bytes ranging from 0 to 4, inclusive.
    fn test_parameter_serdes(original_parameter: &Parameter) {
        for trailing_bytes in 0..MAX_TRAILING_BYTES {
            let mut buffer = serialize(original_parameter);
            for _ in 0..trailing_bytes {
                buffer.push(0xa0);
            }
            let (remainder, parameter) = parse_parameter(&buffer).unwrap();
            assert_eq!(remainder.len(), trailing_bytes);
            assert_eq!(&parameter, original_parameter);
        }
    }

    // Test HeartbeatInfo Parameter

    const HEARTBEAT_INFO_PAYLOAD_BYTES: &[u8] = &[
        0x02, 0x00, 0x07, 0xe4, 0x0a, 0x0a, 0x0a, 0x65, // 0000: .......e
        0x70, 0x3a, 0x52, 0xd7, 0x00, 0x88, 0xff, 0xff, // 0008: p:R.....
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0010:  .......
        0x20, 0x00, 0x00, 0x00, 0x02, 0x99, 0x24, 0x00, // 0018:  .....$.
        0x01, 0x00, 0x00, 0x00, 0xf3, 0x83, 0xe1, 0x85, // 0020: ........
        0xa0, 0xa6, 0x76, 0xca, // 0028: ..v.
    ];
    fn heartbeat_info() -> Parameter {
        Parameter::HeartbeatInfo(HEARTBEAT_INFO_PAYLOAD_BYTES.to_vec())
    }
    const HEARTBEAT_INFO_BYTES: &[u8] = &[
        0x00, 0x01, 0x00, 0x30, 0x02, 0x00, 0x07, 0xe4, // 0000: ...0....
        0x0a, 0x0a, 0x0a, 0x65, 0x70, 0x3a, 0x52, 0xd7, // 0008: ...ep:R.
        0x00, 0x88, 0xff, 0xff, 0x20, 0x00, 0x00, 0x00, // 0010: .... ...
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, // 0018: .... ...
        0x02, 0x99, 0x24, 0x00, 0x01, 0x00, 0x00, 0x00, // 0020: ..$.....
        0xf3, 0x83, 0xe1, 0x85, 0xa0, 0xa6, 0x76, 0xca, // 0028: ......v.
    ];
    #[test]
    fn test_heartbeat_info() {
        test_parameter(heartbeat_info(), HEARTBEAT_INFO_BYTES);
    }
    const TEST_HEARTBEAT_INFO_PAYLOAD_MAX_LENGTH: usize = 4;
    #[test]
    fn test_heartbeat_info_full() {
        for payload in u8_test_lists(TEST_HEARTBEAT_INFO_PAYLOAD_MAX_LENGTH) {
            test_parameter_serdes(&Parameter::HeartbeatInfo(payload));
        }
    }

    // Test IPv4Address Parameter

    fn ipv4_address() -> Parameter {
        Parameter::IPv4Address(IPv4Address::from_bytes(&[127, 0, 0, 1]))
    }

    const IPV4_ADDRESS_BYTES: &[u8] = &[
        0x00, 0x05, 0x00, 0x08, 0x7f, 0x00, 0x00, 0x01, // 0000: ........
    ];

    #[test]
    fn test_ipv4_address() {
        test_parameter(ipv4_address(), IPV4_ADDRESS_BYTES);
    }
    #[test]
    fn test_ipv4_address_full() {
        for &address in U32_TEST_VALUES {
            let parameter = Parameter::IPv4Address(IPv4Address { value: address });
            test_parameter_serdes(&parameter);
        }
    }

    // Test IPv6Address Parameter

    fn ipv6_address() -> Parameter {
        Parameter::IPv6Address(IPv6Address::from_bytes(&[
            // fe80:0:0:0:a00:27ff:fe19:f737
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x27, 0xff, 0xfe, 0x19,
            0xf7, 0x37,
        ]))
    }

    const IPV6_ADDRESS_BYTES: &[u8] = &[
        0x00, 0x06, 0x00, 0x14, 0xfe, 0x80, 0x00, 0x00, // 0000: ........
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x27, 0xff, // 0008: ......'.
        0xfe, 0x19, 0xf7, 0x37, // 0010: ...7
    ];

    #[test]
    fn test_ipv6_address() {
        test_parameter(ipv6_address(), IPV6_ADDRESS_BYTES);
    }

    // Test StateCookie Parameter

    const STATE_COOKIE_PAYLOAD_BYTES: &[u8] = &[
        0x9a, 0x92, 0x48, 0xf6, 0x4e, 0xd2, 0x77, 0x10, // 0000: ..H.N.w.
        0xac, 0x44, 0x33, 0x6c, 0x52, 0x4a, 0xb5, 0x40, // 0008: .D3lRJ.@
        0x4c, 0x78, 0xb5, 0x5f, 0x00, 0x00, 0x00, 0x00, // 0010: Lx._....
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0018: ........
        0x00, 0x00, 0x00, 0x00, 0xec, 0x96, 0xb8, 0x6a, // 0020: .......j
        0xf5, 0xae, 0x26, 0x6a, 0x00, 0x00, 0x00, 0x00, // 0028: ..&j....
        0x00, 0x00, 0x00, 0x00, 0xbd, 0x90, 0x8a, 0xae, // 0030: ........
        0x7e, 0x11, 0x68, 0x14, 0x0a, 0x00, 0x0a, 0x00, // 0038: ~.h.....
        0x6b, 0xcb, 0x3c, 0xd0, 0x02, 0x00, 0x9a, 0xe4, // 0040: k.<.....
        0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 0048: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0050: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0058: ........
        0xe4, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 0060: ........
        0x80, 0x02, 0x00, 0x24, 0x8f, 0x6d, 0x98, 0xb9, // 0068: ...$.m..
        0x3b, 0x0e, 0x63, 0x5c, 0x2e, 0x5e, 0x34, 0xf1, // 0070: ;.c\.^4.
        0x57, 0x7c, 0x89, 0x79, 0xd3, 0x17, 0x3c, 0x2f, // 0078: W|.y..</
        0xe9, 0xed, 0x82, 0xd3, 0x03, 0x41, 0xb5, 0x25, // 0080: .....A.%
        0xe2, 0xb0, 0x7b, 0x35, 0x00, 0x00, 0x00, 0x00, // 0088: ..{5....
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0090: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0098: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00a0: ........
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, // 00a8: .... ...
        0x01, 0x00, 0x00, 0x44, 0x6a, 0x26, 0xae, 0xf5, // 00b0: ...Dj&..
        0x00, 0x01, 0xa0, 0x00, 0x00, 0x0a, 0xff, 0xff, // 00b8: ........
        0x97, 0xb6, 0xcb, 0xfc, 0x00, 0x05, 0x00, 0x08, // 00c0: ........
        0x7f, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00, 0x08, // 00c8: ........
        0x0a, 0x00, 0x02, 0x0f, 0x00, 0x05, 0x00, 0x08, // 00d0: ........
        0x0a, 0x0a, 0x0a, 0x65, 0x00, 0x05, 0x00, 0x08, // 00d8: ...e....
        0xac, 0x11, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x06, // 00e0: ........
        0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04, // 00e8: ........
        0xc0, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, // 00f0: ........
        0x7f, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00, 0x08, // 00f8: ........
        0x0a, 0x00, 0x02, 0x0f, 0x00, 0x05, 0x00, 0x08, // 0100: ........
        0x0a, 0x0a, 0x0a, 0x65, 0x00, 0x05, 0x00, 0x08, // 0108: ...e....
        0xac, 0x11, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 0110: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0118: ........
        0x00, 0x00, 0x00, 0x00, // 0120: ....
    ];
    fn state_cookie() -> Parameter {
        Parameter::StateCookie(STATE_COOKIE_PAYLOAD_BYTES.to_vec())
    }
    const STATE_COOKIE_BYTES: &[u8] = &[
        0x00, 0x07, 0x01, 0x28, 0x9a, 0x92, 0x48, 0xf6, // 0000: ...(..H.
        0x4e, 0xd2, 0x77, 0x10, 0xac, 0x44, 0x33, 0x6c, // 0008: N.w..D3l
        0x52, 0x4a, 0xb5, 0x40, 0x4c, 0x78, 0xb5, 0x5f, // 0010: RJ.@Lx._
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0018: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0020: ........
        0xec, 0x96, 0xb8, 0x6a, 0xf5, 0xae, 0x26, 0x6a, // 0028: ...j..&j
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0030: ........
        0xbd, 0x90, 0x8a, 0xae, 0x7e, 0x11, 0x68, 0x14, // 0038: ....~.h.
        0x0a, 0x00, 0x0a, 0x00, 0x6b, 0xcb, 0x3c, 0xd0, // 0040: ....k.<.
        0x02, 0x00, 0x9a, 0xe4, 0x7f, 0x00, 0x00, 0x01, // 0048: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0050: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0058: ........
        0x00, 0x00, 0x00, 0x00, 0xe4, 0x07, 0x01, 0x00, // 0060: ........
        0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0x00, 0x24, // 0068: .......$
        0x8f, 0x6d, 0x98, 0xb9, 0x3b, 0x0e, 0x63, 0x5c, // 0070: .m..;.c\
        0x2e, 0x5e, 0x34, 0xf1, 0x57, 0x7c, 0x89, 0x79, // 0078: .^4.W|.y
        0xd3, 0x17, 0x3c, 0x2f, 0xe9, 0xed, 0x82, 0xd3, // 0080: ..</....
        0x03, 0x41, 0xb5, 0x25, 0xe2, 0xb0, 0x7b, 0x35, // 0088: .A.%..{5
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0090: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0098: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00a0: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00a8: ........
        0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x44, // 00b0:  ......D
        0x6a, 0x26, 0xae, 0xf5, 0x00, 0x01, 0xa0, 0x00, // 00b8: j&......
        0x00, 0x0a, 0xff, 0xff, 0x97, 0xb6, 0xcb, 0xfc, // 00c0: ........
        0x00, 0x05, 0x00, 0x08, 0x7f, 0x00, 0x00, 0x01, // 00c8: ........
        0x00, 0x05, 0x00, 0x08, 0x0a, 0x00, 0x02, 0x0f, // 00d0: ........
        0x00, 0x05, 0x00, 0x08, 0x0a, 0x0a, 0x0a, 0x65, // 00d8: .......e
        0x00, 0x05, 0x00, 0x08, 0xac, 0x11, 0x00, 0x01, // 00e0: ........
        0x00, 0x0c, 0x00, 0x06, 0x00, 0x05, 0x00, 0x00, // 00e8: ........
        0x80, 0x00, 0x00, 0x04, 0xc0, 0x00, 0x00, 0x04, // 00f0: ........
        0x00, 0x05, 0x00, 0x08, 0x7f, 0x00, 0x00, 0x01, // 00f8: ........
        0x00, 0x05, 0x00, 0x08, 0x0a, 0x00, 0x02, 0x0f, // 0100: ........
        0x00, 0x05, 0x00, 0x08, 0x0a, 0x0a, 0x0a, 0x65, // 0108: .......e
        0x00, 0x05, 0x00, 0x08, 0xac, 0x11, 0x00, 0x01, // 0110: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0118: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0120: ........
    ];

    #[test]
    fn test_state_cookie() {
        test_parameter(state_cookie(), STATE_COOKIE_BYTES);
    }

    // Test UnrecognizedParameter Parameter

    fn unrecognized_parameter() -> Parameter {
        Parameter::UnrecognizedParameter(serialize(&Parameter::Unknown(
            0xfffe,
            vec![0x00, 0x08, 0x00, 0x01, 0x02, 0x03],
        )))
    }
    const UNRECOGNIZED_PARAMETER_BYTES: &[u8] = &[
        0x00, 0x08, 0x00, 0x10, 0xff, 0xfe, 0x00, 0x0a, // 0000: ........
        0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, // 0008: ........
    ];
    fn unrecognized_parameter_tests() -> Vec<Parameter> {
        vec![
            Parameter::Unknown(0xfffe, vec![0xff, 0xfe, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03]),
            Parameter::Unknown(0xffff, vec![0xff, 0xff, 0x00, 0x04]),
            Parameter::IPv4Address(IPv4Address::from_bytes(&[127, 0, 0, 1])),
            Parameter::IPv6Address(IPv6Address::from_bytes(&[
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x5e, 0x60, 0xff, 0xfe, 0xeb,
                0x23, 0x75,
            ])),
        ]
    }
    #[test]
    fn test_unrecognized_parameter() {
        test_parameter(unrecognized_parameter(), UNRECOGNIZED_PARAMETER_BYTES);
    }
    #[test]
    fn test_unrecognized_parameter_full() {
        for parameter in unrecognized_parameter_tests() {
            let parameter = serialize(&parameter);
            test_parameter_serdes(&Parameter::UnrecognizedParameter(parameter));
        }
    }

    // Test CookiePreservative Parameter

    fn cookie_preservative_parameter() -> Parameter {
        Parameter::CookiePreservative(0xfffe0201)
    }
    const COOKIE_PRESERVATIVE_BYTES: &[u8] = &[
        0x00, 0x09, 0x00, 0x08, 0xff, 0xfe, 0x02, 0x01, // 0000: ........
    ];
    #[test]
    fn test_cookie_preservative_parameter() {
        test_parameter(cookie_preservative_parameter(), COOKIE_PRESERVATIVE_BYTES);
    }
    #[test]
    fn test_cookie_preservative_parameter_full() {
        for &lifespan_increment in U32_TEST_VALUES {
            test_parameter_serdes(&Parameter::CookiePreservative(lifespan_increment));
        }
    }

    // Test HostNameAddress Parameter

    fn host_name_address_parameter() -> Parameter {
        Parameter::HostNameAddress("example.com".to_owned())
    }
    const HOST_NAME_ADDRESS_BYTES: &[u8] = &[
        0x00, 0x0b, 0x00, 0x10, 0x65, 0x78, 0x61, 0x6d, // 0000: ....exam
        0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, // 0008: ple.com.
    ];
    const HOST_NAME_ADDRESS_TEST_VALUES: &[&str] = &[
        "x",
        "example.com",
        "3.141592653589793238462643383279502884197169399375105820974944592.com",
    ];
    #[test]
    fn test_host_name_address_parameter() {
        test_parameter(host_name_address_parameter(), HOST_NAME_ADDRESS_BYTES);
    }
    #[test]
    fn test_host_name_address_parameter_full() {
        for hostname in HOST_NAME_ADDRESS_TEST_VALUES {
            test_parameter_serdes(&Parameter::HostNameAddress(hostname.to_string()));
        }
    }

    // Test SupportedAddressTypes Parameter

    fn supported_address_types() -> Parameter {
        Parameter::SupportedAddressTypes(vec![5, 6])
    }
    const SUPPORTED_ADDRESS_TYPES_BYTES: &[u8] = &[
        0x00, 0x0c, 0x00, 0x08, 0x00, 0x05, 0x00, 0x06, // 0000: ........
    ];
    const SUPPORTED_ADDRESS_TYPES_TEST_VALUES: &[&[u16]] = &[
        &[],
        &[IPV4ADDRESS_TYPE],
        &[IPV6ADDRESS_TYPE],
        &[IPV4ADDRESS_TYPE, IPV6ADDRESS_TYPE],
    ];
    #[test]
    fn test_supported_address_types() {
        test_parameter(supported_address_types(), SUPPORTED_ADDRESS_TYPES_BYTES);
    }
    #[test]
    fn test_supported_address_types_full() {
        for address_types in SUPPORTED_ADDRESS_TYPES_TEST_VALUES {
            test_parameter_serdes(&Parameter::SupportedAddressTypes(address_types.to_vec()));
        }
    }

    // Test ECNCapable Parameter

    fn ecn_capable() -> Parameter {
        Parameter::ECNCapable
    }
    const ECN_CAPABLE_BYTES: &[u8] = &[
        0x80, 0x00, 0x00, 0x04, // 0000: ....
    ];
    #[test]
    fn test_ecn_capable() {
        test_parameter(ecn_capable(), ECN_CAPABLE_BYTES);
    }

    // Test ForwardTSNSupported Parameter

    fn forward_tsn_supported() -> Parameter {
        Parameter::ForwardTSNSupported
    }
    const FORWARD_TSN_SUPPORTED_BYTES: &[u8] = &[
        0xc0, 0x00, 0x00, 0x04, // 0000: ....
    ];
    #[test]
    fn test_forward_tsn_supported() {
        test_parameter(forward_tsn_supported(), FORWARD_TSN_SUPPORTED_BYTES);
    }
}
