//! Utility functions useful for debugging and development.

pub mod buffer;
pub mod serial;
#[cfg(test)]
pub mod tests;

use std;
use std::fmt;

/// Generate a hexdump of the provided byte slice.
pub fn hexdump(
    f: &mut fmt::Formatter,
    prefix: &str,
    buffer: &[u8],
) -> std::result::Result<(), std::fmt::Error> {
    const COLUMNS: usize = 16;
    let mut offset: usize = 0;
    if buffer.len() == 0 {
        // For a zero-length buffer, at least print an offset instead of
        // nothing.
        try!(write!(f, "{}{:04x}: ", prefix, 0));
    }
    while offset < buffer.len() {
        try!(write!(f, "{}{:04x}: ", prefix, offset));

        // Determine row byte range
        let next_offset = offset + COLUMNS;
        let (row_size, padding) = if next_offset <= buffer.len() {
            (COLUMNS, 0)
        } else {
            (buffer.len() - offset, next_offset - buffer.len())
        };
        let row = &buffer[offset..offset + row_size];

        // Print hex representation
        for b in row {
            try!(write!(f, "{:02x} ", b));
        }
        for _ in 0..padding {
            try!(write!(f, "   "));
        }

        // Print ASCII representation
        for b in row {
            try!(write!(
                f,
                "{}",
                match *b {
                    c @ 0x20...0x7E => c as char,
                    _ => '.',
                }
            ));
        }

        offset += COLUMNS;
        if offset < buffer.len() {
            try!(writeln!(f, ""));
        }
    }
    Ok(())
}

/// A byte slice wrapped in Hex is printable as a hex dump.
#[allow(dead_code)]
pub struct Hex<'a>(pub &'a [u8]);
impl<'a> fmt::Display for Hex<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hexdump(f, "", self.0)
    }
}

/// Wrap the provided byte slice in a Hex to allow it to be printable as a hex dump.
pub fn hex(bytes: &[u8]) -> Hex {
    Hex(bytes)
}

/// For debugging purposes, return a short hash of the supplied byte buffer.
pub fn shorthash(bytes: &[u8]) -> String {
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::new();
    hasher.input(bytes);
    let output = hasher.result();
    format!(
        "{:x}{:x}{:x}{:x}",
        output[0], output[1], output[2], output[3]
    )
}
