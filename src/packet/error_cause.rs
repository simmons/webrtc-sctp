//! SCTP error cause parsing and synthesis

use std::fmt;

use nom::{be_u16, be_u32, rest, IResult};

use packet::parameter::{parse_parameter, Parameter};
use packet::writer::{Result as WriterResult, Writer};
use util::hexdump;

// Error Cause types
const INVALID_STREAM_IDENTIFIER_TYPE: u16 = 1;
const MISSING_MANDATORY_PARAMETER_TYPE: u16 = 2;
const STALE_COOKIE_TYPE: u16 = 3;
const OUT_OF_RESOURCE_TYPE: u16 = 4;
const UNRESOLVABLE_ADDRESS_TYPE: u16 = 5;
const UNRECOGNIZED_CHUNK_TYPE_TYPE: u16 = 6;
const INVALID_MANDATORY_PARAMETER_TYPE: u16 = 7;
const UNRECOGNIZED_PARAMETERS_TYPE: u16 = 8;
const NO_USER_DATA_TYPE: u16 = 9;
const COOKIE_RECEIVED_WHILE_SHUTTING_DOWN_TYPE: u16 = 10;
const RESTART_ASSOCIATION_WITH_NEW_ADDRESSES_TYPE: u16 = 11;
const USER_INITIATED_ABORT_TYPE: u16 = 12;
const PROTOCOL_VIOLATION_TYPE: u16 = 13;

// Error Causes
#[derive(Clone, Debug, PartialEq)]
pub enum ErrorCause {
    InvalidStreamIdentifier(u16),
    MissingMandatoryParameter(Vec<u16>),
    StaleCookie(u32),
    OutOfResource,
    UnresolvableAddress(Parameter),
    UnrecognizedChunkType(Vec<u8>),
    InvalidMandatoryParameter,
    UnrecognizedParameters(Vec<Parameter>),
    NoUserData(u32),
    CookieReceivedWhileShuttingDown,
    RestartAssociationWithNewAddresses(Vec<Parameter>),
    UserInitiatedAbort(Vec<u8>), // "Upper Layer Abort Reason"
    ProtocolViolation(Vec<u8>),  // "Additional Information"
    Unknown(u16, Vec<u8>),
}

// Display an error cause
impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ErrorCause::InvalidStreamIdentifier(ref stream_id) => {
                writeln!(f, "InvalidStreamIdentifier {}", stream_id)
            }
            ErrorCause::MissingMandatoryParameter(ref parameter_types) => {
                write!(f, "MissingMandatoryParameter ")?;
                for parameter_type in parameter_types {
                    write!(f, "{} ", parameter_type)?;
                }
                writeln!(f, "")
            }
            ErrorCause::StaleCookie(ref staleness) => writeln!(f, "StaleCookieError {}", staleness),
            ErrorCause::OutOfResource => writeln!(f, "OutOfResource"),
            ErrorCause::UnresolvableAddress(ref parameter) => {
                writeln!(f, "UnresolvableAddress {}", parameter)
            }
            ErrorCause::UnrecognizedChunkType(ref chunk_types) => {
                write!(f, "UnrecognizedChunkType ")?;
                for chunk_type in chunk_types {
                    write!(f, "{} ", chunk_type)?;
                }
                writeln!(f, "")
            }
            ErrorCause::InvalidMandatoryParameter => writeln!(f, "InvalidMandatoryParameter"),
            ErrorCause::UnrecognizedParameters(ref parameters) => {
                write!(f, "UnrecognizedParameters ")?;
                for parameter in parameters {
                    write!(f, "{} ", parameter)?;
                }
                writeln!(f, "")
            }
            ErrorCause::NoUserData(ref tsn) => writeln!(f, "NoUserData {}", tsn),
            ErrorCause::CookieReceivedWhileShuttingDown => {
                writeln!(f, "CookieReceivedWhileShuttingDown")
            }
            ErrorCause::RestartAssociationWithNewAddresses(ref parameters) => {
                write!(f, "RestartAssociationWithNewAddresses")?;
                for parameter in parameters {
                    write!(f, "{} ", parameter)?;
                }
                writeln!(f, "")
            }
            ErrorCause::UserInitiatedAbort(ref upper_layer_abort_reason) => {
                writeln!(f, "UserInitiatedAbort")?;
                hexdump(f, "\t\t", upper_layer_abort_reason)
            }
            ErrorCause::ProtocolViolation(ref additional_information) => {
                writeln!(f, "ProtocolViolation")?;
                hexdump(f, "\t\t", additional_information)
            }
            ErrorCause::Unknown(tag, ref value) => {
                writeln!(f, "UnknownErrorCauseCode({})", tag)?;
                hexdump(f, "\t\t", value)
            }
        }
    }
}

// InvalidStreamIdentifier Error Cause

named!(invalidstreamidentifier_error_cause<&[u8], ErrorCause>, do_parse!(
    stream_id:              be_u16 >>
                            be_u16 >> // reserved
    ( ErrorCause::InvalidStreamIdentifier(stream_id) )
));

// MissingMandatoryParameter Error Cause

named!(missingmandatoryparameter_error_cause<&[u8], ErrorCause>, do_parse!(
    count:                  be_u32 >>
    missing_param_types:    count!(be_u16, count as usize) >>
    ( ErrorCause::MissingMandatoryParameter(missing_param_types) )
));

// Stale Cookie Error Cause

named!(stalecookie_error_cause<&[u8], ErrorCause>, do_parse!(
    staleness:              be_u32 >>
    ( ErrorCause::StaleCookie(staleness) )
));

// Out Of Resource Error Cause

named!(outofresource_error_cause<&[u8], ErrorCause>, do_parse!(
    ( ErrorCause::OutOfResource )
));

// UnresolvableAddress Error Cause

named!(unresolvableaddress_error_cause<&[u8], ErrorCause>, do_parse!(
    parameter: parse_parameter >>
    ( ErrorCause::UnresolvableAddress(parameter) )
));

// Unrecognized Chunk Type Error Cause

named!(unrecognizedchunktype_error_cause<&[u8], ErrorCause>, do_parse!(
    chunk: rest >>
    ( ErrorCause::UnrecognizedChunkType(chunk.to_owned()) )
));

// Invalid Mandatory Parameter Error Cause

named!(invalidmandatoryparameter_error_cause<&[u8], ErrorCause>, do_parse!(
    ( ErrorCause::InvalidMandatoryParameter )
));

// Unrecognized Parameters Error Cause

named!(unrecognizedparameters_error_cause<&[u8], ErrorCause>, do_parse!(
    parameters: many1!(parse_parameter) >>
    ( ErrorCause::UnrecognizedParameters(parameters) )
));

// No User Data Error Cause

named!(nouserdata_error_cause<&[u8], ErrorCause>, do_parse!(
    tsn: be_u32 >>
    ( ErrorCause::NoUserData(tsn) )
));

// Cookie Received While Shutting Down Error Cause

named!(cookiereceivedwhileshuttingdown_error_cause<&[u8], ErrorCause>, do_parse!(
    ( ErrorCause::CookieReceivedWhileShuttingDown )
));

// RestartAssociationWithNewAddresses Error Cause

named!(restartassociationwithnewaddresses_error_cause<&[u8], ErrorCause>, do_parse!(
    parameters: many1!(parse_parameter) >>
    ( ErrorCause::RestartAssociationWithNewAddresses(parameters) )
));

// UserInitiatedAbort Error Cause

named!(userinitiatedabort_error_cause<&[u8], ErrorCause>, do_parse!(
    upper_layer_abort_reason: rest >>
    ( ErrorCause::UserInitiatedAbort(upper_layer_abort_reason.to_owned()) )
));

// ProtocolViolation Error Cause

named!(protocolviolation_error_cause<&[u8], ErrorCause>, do_parse!(
    additional_information: rest >>
    ( ErrorCause::ProtocolViolation(additional_information.to_owned()) )
));

// NOTE: RFC 4960 doesn't explicitly indicate padding for error cause TLVs (tag-length-value), but
// implies it via reference to the Section 3.2.1 parameter structure.  The Linux kernel SCTP
// implementation expects padding on error cause TLVs, so we'll assume that is correct.

#[inline]
fn error_cause_dispatch(tag: u16, value: &[u8]) -> IResult<&[u8], ErrorCause> {
    match tag {
        INVALID_STREAM_IDENTIFIER_TYPE => invalidstreamidentifier_error_cause(value),
        MISSING_MANDATORY_PARAMETER_TYPE => missingmandatoryparameter_error_cause(value),
        STALE_COOKIE_TYPE => stalecookie_error_cause(value),
        OUT_OF_RESOURCE_TYPE => outofresource_error_cause(value),
        UNRESOLVABLE_ADDRESS_TYPE => unresolvableaddress_error_cause(value),
        UNRECOGNIZED_CHUNK_TYPE_TYPE => unrecognizedchunktype_error_cause(value),
        INVALID_MANDATORY_PARAMETER_TYPE => invalidmandatoryparameter_error_cause(value),
        UNRECOGNIZED_PARAMETERS_TYPE => unrecognizedparameters_error_cause(value),
        NO_USER_DATA_TYPE => nouserdata_error_cause(value),
        COOKIE_RECEIVED_WHILE_SHUTTING_DOWN_TYPE => {
            cookiereceivedwhileshuttingdown_error_cause(value)
        }
        RESTART_ASSOCIATION_WITH_NEW_ADDRESSES_TYPE => {
            restartassociationwithnewaddresses_error_cause(value)
        }
        USER_INITIATED_ABORT_TYPE => userinitiatedabort_error_cause(value),
        PROTOCOL_VIOLATION_TYPE => protocolviolation_error_cause(value),
        _ => Ok((&[], ErrorCause::Unknown(tag, value.to_owned()))),
    }
}

named!(pub parse_error_cause<&[u8], ErrorCause>, do_parse!(
    error_cause:  parse_tlv!(error_cause_dispatch) >> ( error_cause )
));

pub fn write_error_cause(writer: &mut Writer, error_cause: &ErrorCause) -> WriterResult<()> {
    match error_cause {
        &ErrorCause::InvalidStreamIdentifier(stream_id) => {
            writer.open_tlv(INVALID_STREAM_IDENTIFIER_TYPE)?;
            writer.write_be16(stream_id)?;
            writer.write_be16(0)?; // reserved
            writer.close_tlv()?;
        }
        &ErrorCause::MissingMandatoryParameter(ref missing_param_types) => {
            writer.open_tlv(MISSING_MANDATORY_PARAMETER_TYPE)?;
            writer.write_be32(missing_param_types.len() as u32)?;
            for missing_param_type in missing_param_types {
                writer.write_be16(*missing_param_type)?;
            }
            writer.close_tlv()?;
        }
        &ErrorCause::StaleCookie(staleness) => {
            writer.open_tlv(STALE_COOKIE_TYPE)?;
            writer.write_be32(staleness)?;
            writer.close_tlv()?;
        }
        &ErrorCause::OutOfResource => {
            writer.open_tlv(OUT_OF_RESOURCE_TYPE)?;
            writer.close_tlv()?;
        }
        &ErrorCause::UnresolvableAddress(ref parameter) => {
            writer.open_tlv(UNRESOLVABLE_ADDRESS_TYPE)?;
            writer.write_parameter(&parameter)?;
            writer.close_tlv()?;
        }
        &ErrorCause::UnrecognizedChunkType(ref chunk) => {
            writer.open_tlv(UNRECOGNIZED_CHUNK_TYPE_TYPE)?;
            writer.write_bytes(chunk)?;
            writer.close_tlv()?;
        }
        &ErrorCause::InvalidMandatoryParameter => {
            writer.open_tlv(INVALID_MANDATORY_PARAMETER_TYPE)?;
            writer.close_tlv()?;
        }
        &ErrorCause::UnrecognizedParameters(ref parameters) => {
            writer.open_tlv(UNRECOGNIZED_PARAMETERS_TYPE)?;
            for parameter in parameters {
                writer.write_parameter(parameter)?;
            }
            writer.close_tlv()?;
        }
        &ErrorCause::NoUserData(tsn) => {
            writer.open_tlv(NO_USER_DATA_TYPE)?;
            writer.write_be32(tsn)?;
            writer.close_tlv()?;
        }
        &ErrorCause::CookieReceivedWhileShuttingDown => {
            writer.open_tlv(COOKIE_RECEIVED_WHILE_SHUTTING_DOWN_TYPE)?;
            writer.close_tlv()?;
        }
        &ErrorCause::RestartAssociationWithNewAddresses(ref parameters) => {
            writer.open_tlv(RESTART_ASSOCIATION_WITH_NEW_ADDRESSES_TYPE)?;
            for parameter in parameters {
                writer.write_parameter(parameter)?;
            }
            writer.close_tlv()?;
        }
        &ErrorCause::UserInitiatedAbort(ref upper_layer_abort_reason) => {
            writer.open_tlv(USER_INITIATED_ABORT_TYPE)?;
            writer.write_bytes(upper_layer_abort_reason)?;
            writer.close_tlv()?;
        }
        &ErrorCause::ProtocolViolation(ref additional_information) => {
            writer.open_tlv(PROTOCOL_VIOLATION_TYPE)?;
            writer.write_bytes(additional_information)?;
            writer.close_tlv()?;
        }
        &ErrorCause::Unknown(ptype, ref data) => {
            writer.open_tlv(ptype)?;
            writer.write_bytes(data)?;
            writer.close_tlv()?;
        }
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::parameter;
    use packet::writer::*;
    use util::tests::*;

    /// How many trailing bytes cases should we test?
    const MAX_TRAILING_BYTES: usize = 5;

    /// Serialize an error cause to a byte vector.
    fn serialize(error_cause: &ErrorCause) -> Vec<u8> {
        let mut writer = WriterOwned::new();
        write_error_cause(&mut writer, error_cause).unwrap();
        writer.to_owned()
    }

    /// Perform basic error cause serialization and deserialization tests
    fn test_error_cause(error_cause: ErrorCause, expected_bytes: &[u8]) {
        // Test serialize
        let buffer = serialize(&error_cause);
        assert_eq!(buffer, expected_bytes);

        // Test parsing
        let (remainder, parsed_error_cause) = parse_error_cause(&buffer).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(&parsed_error_cause, &error_cause);

        // Test serialization-deserialization with variable number of trailing bytes.
        test_error_cause_serdes(&error_cause);
    }

    /// Test serialization and deserialization of a particular error_cause with
    /// a variable number of trailing bytes ranging from 0 to 4, inclusive.
    fn test_error_cause_serdes(original_error_cause: &ErrorCause) {
        for trailing_bytes in 0..MAX_TRAILING_BYTES {
            let mut buffer = serialize(original_error_cause);
            for _ in 0..trailing_bytes {
                buffer.push(0xa0);
            }
            let (remainder, error_cause) = parse_error_cause(&buffer).unwrap();
            assert_eq!(remainder.len(), trailing_bytes);
            assert_eq!(&error_cause, original_error_cause);
        }
    }

    // Test InvalidStreamIdentifier Error Cause

    fn invalid_stream_identifier() -> ErrorCause {
        ErrorCause::InvalidStreamIdentifier(0x42)
    }
    const INVALID_STREAM_IDENTIFIER_BYTES: &[u8] = &[
        0x00, 0x01, 0x00, 0x08, 0x00, 0x42, 0x00, 0x00, // 0000: .....B..
    ];
    #[test]
    fn test_invalid_stream_identifier() {
        test_error_cause(invalid_stream_identifier(), INVALID_STREAM_IDENTIFIER_BYTES);
    }
    #[test]
    fn test_invalid_stream_identifier_full() {
        for &stream_id in U16_TEST_VALUES {
            test_error_cause_serdes(&ErrorCause::InvalidStreamIdentifier(stream_id));
        }
    }

    // Test MissingMandatoryParameter Error Cause

    fn missing_mandatory_parameter() -> ErrorCause {
        ErrorCause::MissingMandatoryParameter(vec![0x0000, 0x8000, 0xFFFF])
    }
    const MISSING_MANDATORY_PARAMETER_BYTES: &[u8] = &[
        0x00, 0x02, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x03, // 0000: ........
        0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0x00, 0x00, // 0008: ........
    ];
    #[test]
    fn test_missing_mandatory_parameter() {
        test_error_cause(
            missing_mandatory_parameter(),
            MISSING_MANDATORY_PARAMETER_BYTES,
        );
    }
    const TEST_PARAM_TYPES_MAX_LENGTH: usize = 4;
    #[test]
    fn test_missing_mandatory_parameter_full() {
        for param_type_list in u16_test_lists(TEST_PARAM_TYPES_MAX_LENGTH) {
            test_error_cause_serdes(&ErrorCause::MissingMandatoryParameter(param_type_list));
        }
    }

    // Test Stale Cookie Error Cause

    fn stale_cookie() -> ErrorCause {
        ErrorCause::StaleCookie(0x01020304)
    }
    const STALE_COOKIE_BYTES: &[u8] = &[
        0x00, 0x03, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, // 0000: ........
    ];
    #[test]
    fn test_stale_cookie() {
        test_error_cause(stale_cookie(), STALE_COOKIE_BYTES);
    }
    #[test]
    fn test_stale_cookie_full() {
        for &staleness in U32_TEST_VALUES {
            test_error_cause_serdes(&ErrorCause::StaleCookie(staleness));
        }
    }

    // Test Out Of Resource Error Cause

    fn out_of_resource() -> ErrorCause {
        ErrorCause::OutOfResource
    }
    const OUT_OF_RESOURCE_BYTES: &[u8] = &[
        0x00, 0x04, 0x00, 0x04, // 0000: ....
    ];
    #[test]
    fn test_out_of_resource() {
        test_error_cause(out_of_resource(), OUT_OF_RESOURCE_BYTES);
    }

    // Test UnresolvableAddress Error Cause

    fn unresolvable_address() -> ErrorCause {
        ErrorCause::UnresolvableAddress(Parameter::IPv4Address(parameter::IPv4Address::from_bytes(
            &[127, 0, 0, 1],
        )))
    }
    const UNRESOLVABLE_ADDRESS_BYTES: &[u8] = &[
        0x00, 0x05, 0x00, 0x0c, 0x00, 0x05, 0x00, 0x08, // 0000: ........
        0x7f, 0x00, 0x00, 0x01, // 0008: ....
    ];
    fn unresolvable_address_parameter_tests() -> Vec<Parameter> {
        vec![
            Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[127, 0, 0, 1])),
            Parameter::IPv6Address(parameter::IPv6Address::from_bytes(&[
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x5e, 0x60, 0xff, 0xfe, 0xeb,
                0x23, 0x75,
            ])),
        ]
    }
    #[test]
    fn test_unresolvable_address() {
        test_error_cause(unresolvable_address(), UNRESOLVABLE_ADDRESS_BYTES);
    }
    #[test]
    fn test_unresolvable_address_full() {
        for parameter in unresolvable_address_parameter_tests() {
            test_error_cause_serdes(&ErrorCause::UnresolvableAddress(parameter));
        }
    }

    // Test Unrecognized Chunk Type Error Cause

    fn unrecognized_chunk_type() -> ErrorCause {
        ErrorCause::UnrecognizedChunkType(vec![0x00, 0x01, 0x02, 0x03])
    }
    const UNRECOGNIZED_CHUNK_TYPE_BYTES: &[u8] = &[
        0x00, 0x06, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03, // 0000: ........
    ];
    #[test]
    fn test_unrecognized_chunk_type() {
        test_error_cause(unrecognized_chunk_type(), UNRECOGNIZED_CHUNK_TYPE_BYTES);
    }
    #[test]
    fn test_unrecognized_chunk_type_full() {
        for chunk_type_list in u8_test_lists(4) {
            test_error_cause_serdes(&ErrorCause::UnrecognizedChunkType(chunk_type_list));
        }
    }

    // Test Invalid Mandatory Parameter Error Cause

    fn invalid_mandatory_parameter() -> ErrorCause {
        ErrorCause::InvalidMandatoryParameter
    }
    const INVALID_MANDATORY_PARAMETER_BYTES: &[u8] = &[
        0x00, 0x07, 0x00, 0x04, // 0000: ....
    ];
    #[test]
    fn test_invalid_mandatory_parameter() {
        test_error_cause(
            invalid_mandatory_parameter(),
            INVALID_MANDATORY_PARAMETER_BYTES,
        );
    }

    // Test Unrecognized Parameters Error Cause

    fn unrecognized_parameters() -> ErrorCause {
        ErrorCause::UnrecognizedParameters(vec![
            parameter::Parameter::Unknown(0xfffe, vec![0x00, 0x08, 0x00, 0x01, 0x02, 0x03]),
            parameter::Parameter::Unknown(0xffff, vec![0x00, 0x04]),
        ])
    }
    const UNRECOGNIZED_PARAMETERS_BYTES: &[u8] = &[
        0x00, 0x08, 0x00, 0x18, 0xff, 0xfe, 0x00, 0x0a, // 0000: ........
        0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, // 0008: ........
        0xff, 0xff, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // 0010: ........
    ];
    fn unrecognized_parameters_tests() -> Vec<Vec<Parameter>> {
        vec![
            vec![parameter::Parameter::Unknown(
                0xfffe,
                vec![0xff, 0xfe, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03],
            )],
            vec![parameter::Parameter::Unknown(
                0xffff,
                vec![0xff, 0xff, 0x00, 0x04],
            )],
            vec![
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[127, 0, 0, 1])),
                Parameter::IPv6Address(parameter::IPv6Address::from_bytes(&[
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x5e, 0x60, 0xff, 0xfe,
                    0xeb, 0x23, 0x75,
                ])),
            ],
        ]
    }
    #[test]
    fn test_unrecognized_parameters() {
        test_error_cause(unrecognized_parameters(), UNRECOGNIZED_PARAMETERS_BYTES);
    }
    #[test]
    fn test_unrecognized_parameters_full() {
        for parameter_list in unrecognized_parameters_tests() {
            test_error_cause_serdes(&ErrorCause::UnrecognizedParameters(parameter_list));
        }
    }

    // Test No User Data Error Cause

    fn no_user_data() -> ErrorCause {
        ErrorCause::NoUserData(0x01020304)
    }
    const NO_USER_DATA_BYTES: &[u8] = &[
        0x00, 0x09, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, // 0000: ........
    ];
    #[test]
    fn test_no_user_data() {
        test_error_cause(no_user_data(), NO_USER_DATA_BYTES);
    }
    #[test]
    fn test_no_user_data_full() {
        for &tsn in U32_TEST_VALUES {
            test_error_cause_serdes(&ErrorCause::NoUserData(tsn));
        }
    }

    // Test Cookie Received While Shutting Down Error Cause

    fn cookie_received_while_shutting_down() -> ErrorCause {
        ErrorCause::CookieReceivedWhileShuttingDown
    }
    const COOKIE_RECEIVED_WHILE_SHUTTING_DOWN_BYTES: &[u8] = &[
        0x00, 0x0a, 0x00, 0x04, // 0000: ....
    ];
    #[test]
    fn test_cookie_received_while_shutting_down() {
        test_error_cause(
            cookie_received_while_shutting_down(),
            COOKIE_RECEIVED_WHILE_SHUTTING_DOWN_BYTES,
        );
    }

    // Test RestartAssociationWithNewAddresses Error Cause

    fn restart_association_with_new_addresses() -> ErrorCause {
        ErrorCause::RestartAssociationWithNewAddresses(vec![
            parameter::Parameter::Unknown(0xfffe, vec![0x00, 0x08, 0x00, 0x01, 0x02, 0x03]),
            parameter::Parameter::Unknown(0xffff, vec![0x00, 0x04]),
        ])
    }
    const RESTART_ASSOCIATION_WITH_NEW_ADDRESSES_BYTES: &[u8] = &[
        0x00, 0x0b, 0x00, 0x18, 0xff, 0xfe, 0x00, 0x0a, // 0000: ........
        0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, // 0008: ........
        0xff, 0xff, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // 0010: ........
    ];
    fn restart_association_with_new_addresses_tests() -> Vec<Vec<Parameter>> {
        vec![
            vec![Parameter::IPv4Address(parameter::IPv4Address::from_bytes(
                &[127, 0, 0, 1],
            ))],
            vec![Parameter::IPv6Address(parameter::IPv6Address::from_bytes(
                &[
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x5e, 0x60, 0xff, 0xfe,
                    0xeb, 0x23, 0x75,
                ],
            ))],
            vec![
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[127, 0, 0, 1])),
                Parameter::IPv6Address(parameter::IPv6Address::from_bytes(&[
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x5e, 0x60, 0xff, 0xfe,
                    0xeb, 0x23, 0x75,
                ])),
            ],
        ]
    }
    #[test]
    fn test_restart_association_with_new_addresses() {
        test_error_cause(
            restart_association_with_new_addresses(),
            RESTART_ASSOCIATION_WITH_NEW_ADDRESSES_BYTES,
        );
    }
    #[test]
    fn test_restart_association_with_new_addresses_full() {
        for parameter_list in restart_association_with_new_addresses_tests() {
            test_error_cause_serdes(&ErrorCause::RestartAssociationWithNewAddresses(
                parameter_list,
            ));
        }
    }

    // Test UserInitiatedAbort Error Cause

    fn user_initiated_abort() -> ErrorCause {
        ErrorCause::UserInitiatedAbort(vec![0x00, 0x01, 0x02, 0x03])
    }
    const USER_INITIATED_ABORT_BYTES: &[u8] = &[
        0x00, 0x0c, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03, // 0000: ........
    ];
    #[test]
    fn test_user_initiated_abort() {
        test_error_cause(user_initiated_abort(), USER_INITIATED_ABORT_BYTES);
    }
    #[test]
    fn test_user_initiated_abort_full() {
        for upper_layer_abort_reason in u8_test_lists(4) {
            test_error_cause_serdes(&ErrorCause::UserInitiatedAbort(upper_layer_abort_reason));
        }
    }

    // Test ProtocolViolation Error Cause

    fn protocol_violation() -> ErrorCause {
        ErrorCause::ProtocolViolation(vec![0x00, 0x01, 0x02, 0x03])
    }
    const PROTOCOL_VIOLATION_BYTES: &[u8] = &[
        0x00, 0x0d, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03, // 0000: ........
    ];
    #[test]
    fn test_protocol_violation() {
        test_error_cause(protocol_violation(), PROTOCOL_VIOLATION_BYTES);
    }
    #[test]
    fn test_protocol_violation_full() {
        for additional_information in u8_test_lists(4) {
            test_error_cause_serdes(&ErrorCause::ProtocolViolation(additional_information));
        }
    }
}
