//! Helper functions and macros related to parsing.

/// Consume an entire SCTP Tag-Length-Value (TLV) structure and return a processed value according
/// to the provided dispatch function.  (A closure doesn't seem to work due to lifetime issues.)
macro_rules! parse_tlv (
    ($i:expr, $dispatch_function:expr) => ({
        use nom::{Err, ErrorKind, be_u16};
        use nom::simple_errors::Context;
        const TAG_LENGTH_HEADER_SIZE: usize = 4;
        let input = $i;
        if input.len() < TAG_LENGTH_HEADER_SIZE {
            // underrun TODO: real error
            Err(Err::Error(Context::Code(input,ErrorKind::Custom(0))))
        } else {
            // Parse tag
            match be_u16(input) {
                Err(e) => Err(e),
                Ok((i, tag)) => {
                    // Parse length
                    match be_u16(i) {
                        Err(e) => Err(e),
                        Ok((i, length)) => {
                            // Validate length
                            if (length as usize) < TAG_LENGTH_HEADER_SIZE {
                                // invalid length field TODO: real error
                                Err(Err::Error(Context::Code(i,ErrorKind::Custom(0))))
                            } else {
                                // Subtract the header size to get the value length
                                let length = length as usize - TAG_LENGTH_HEADER_SIZE;
                                // Account for padding
                                let padding = (4 - length % 4) % 4;
                                let padded_length = length + padding;
                                if padded_length > i.len() {
                                    // not incomplete -- we should always have the full TLV
                                    Err(Err::Error(Context::Code(i,ErrorKind::Custom(0))))
                                } else {
                                    // Split slices into the data which is part of this TLV
                                    // (not including padding) and the rest of the input stream
                                    // which follows any trailing padding.
                                    let value_data = &i[..length];
                                    let remaining_input = &i[padded_length..];

                                    // Dispatch
                                    match $dispatch_function(tag, value_data) {
                                        Ok((i,value)) => {
                                            // The value data should be completely consumed
                                            if i.len() != 0 {
                                                Err(Err::Error(Context::Code(i,ErrorKind::Custom(0))))
                                            } else {
                                                Ok((remaining_input, value))
                                            }
                                        },
                                        Err(Err::Incomplete(_)) => {
                                            // The TLV parser should always have complete data
                                            Err(Err::Error(Context::Code(i,ErrorKind::Custom(0))))
                                        },
                                        Err(e) => Err(e),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    ($i:expr,) => ( parse_tlv!($i) );
);
