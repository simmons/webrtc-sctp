use std::error;
use std::fmt;
use std::io;

/// The errors that may be returned by SCTP functions are categorized into these enum variants.
#[derive(Debug)]
pub enum SctpError {
    Io(io::Error),
    #[allow(dead_code)]
    ReadUnderrun,
    InvalidPacket,
    BadChecksum,
    BadState,
    ExpectedBeginningFragment,
    UnexpectedBeginningFragment,
    UnexpectedSSN,
    SendQueueFull,
    CommandQueueFull,
    Closed,
    Timeout,
}

#[must_use]
pub type SctpResult<T> = ::std::result::Result<T, SctpError>;

impl fmt::Display for SctpError {
    /// Provide human-readable descriptions of the errors
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SctpError::Io(ref e) => write!(f, "IO error: {}", e),
            SctpError::ReadUnderrun => write!(f, "read underrun"),
            SctpError::InvalidPacket => write!(f, "invalid packet"),
            SctpError::BadChecksum => write!(f, "bad checksum"),
            SctpError::BadState => write!(f, "bad state"),
            SctpError::ExpectedBeginningFragment => write!(f, "expected beginning fragment"),
            SctpError::UnexpectedBeginningFragment => write!(f, "unexpected beginning fragment"),
            SctpError::UnexpectedSSN => write!(f, "unexpected ssn"),
            SctpError::SendQueueFull => write!(f, "send queue full"),
            SctpError::CommandQueueFull => write!(f, "command queue full"),
            SctpError::Closed => write!(f, "resource is closed"),
            SctpError::Timeout => write!(f, "timeout"),
        }
    }
}

impl error::Error for SctpError {
    /// Provide terse descriptions of the errors.
    fn description(&self) -> &str {
        // "The description should only be used for a simple message. It
        // should not contain newlines or sentence-ending punctuation,
        // to facilitate embedding in larger user-facing strings. For
        // showing formatted error messages with more information see
        // Display."
        match *self {
            SctpError::Io(ref e) => error::Error::description(e),
            SctpError::ReadUnderrun => "A read underrun occured",
            SctpError::InvalidPacket => "Invalid packet",
            SctpError::BadChecksum => "Bad checksum",
            SctpError::BadState => "Bad state",
            SctpError::ExpectedBeginningFragment => {
                "Expected beginning fragment; received middle or end."
            }
            SctpError::UnexpectedBeginningFragment => "Unexpected beginning fragment",
            SctpError::UnexpectedSSN => "Unexpected SSN",
            SctpError::SendQueueFull => "Send queue full",
            SctpError::CommandQueueFull => "Command queue full",
            SctpError::Closed => "Resource is closed",
            SctpError::Timeout => "Timeout",
        }
    }
    /// For errors which encapsulate another error, allow the caller to fetch the contained error.
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            SctpError::Io(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for SctpError {
    fn from(err: io::Error) -> SctpError {
        SctpError::Io(err)
    }
}
