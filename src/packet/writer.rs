//! A Writer provides functions to help render an SCTP packet from its constituent packet, chunk,
//! parameter, and error code structures.

use std::fmt;

use packet::chunk::ChunkWriter;
use packet::error_cause::{write_error_cause, ErrorCause};
use packet::parameter::{write_parameter, Parameter};
use packet::SctpHeader;

const DEFAULT_MTU: usize = 1500;

pub enum ErrorKind {
    MtuReached,
}

impl fmt::Debug for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &ErrorKind::MtuReached => write!(f, "MtuReached"),
        }
    }
}

pub type Result<T> = ::std::result::Result<T, ErrorKind>;

pub trait Writer {
    fn write_byte(&mut self, value: u8) -> Result<()>;
    fn write_bytes(&mut self, value: &[u8]) -> Result<()>;
    fn write_byte_offset(&mut self, position: usize, value: u8) -> Result<()>;
    fn len(&self) -> usize;
    fn mtu(&self) -> usize;
    fn push_tlv(&mut self, position: usize);
    fn pop_tlv(&mut self) -> Option<usize>;
    fn write_chunk(&mut self, chunk_writer: &ChunkWriter) -> Result<()>;
    fn write_parameter(&mut self, parameter: &Parameter) -> Result<()>;
    fn write_error_cause(&mut self, error_cause: &ErrorCause) -> Result<()>;
    fn bytes(&mut self) -> Result<&[u8]>;

    fn write_be8(&mut self, value: u8) -> Result<()> {
        self.write_byte(value)
    }
    fn write_be16(&mut self, value: u16) -> Result<()> {
        self.write_byte(((value >> 8) & 0xFF) as u8)?;
        self.write_byte(((value >> 0) & 0xFF) as u8)?;
        Ok(())
    }
    fn write_be32(&mut self, value: u32) -> Result<()> {
        self.write_byte(((value >> 24) & 0xFF) as u8)?;
        self.write_byte(((value >> 16) & 0xFF) as u8)?;
        self.write_byte(((value >> 8) & 0xFF) as u8)?;
        self.write_byte(((value >> 0) & 0xFF) as u8)?;
        Ok(())
    }
    fn open_tlv(&mut self, tag: u16) -> Result<()> {
        // Push the current position to the stack, so we can track the start position of this TLV.
        let length = self.len();
        self.push_tlv(length);
        // Write the tag.
        self.write_be16(tag)?;
        // Write a placeholder for the length, which will be populated in close_tlv().
        self.write_be16(0u16)?;
        Ok(())
    }

    fn open_tlv_chunk(&mut self, tag: u8, flags: u8) -> Result<()> {
        self.open_tlv(((tag as u16) << 8) | (flags as u16))
    }

    fn close_tlv(&mut self) -> Result<()> {
        // Pop the position of the current TLV from the stack
        let tlv_start = match self.pop_tlv() {
            Some(p) => p,
            None => panic!("Imbalanced TLV"),
        };
        // Determine the length of this TLV.
        let length = self.len() - tlv_start;
        // Determine the index of the TLV length field.
        let length_index = tlv_start + 2;
        // Write the length.
        self.write_byte_offset(length_index, ((length >> 8) & 0xFF) as u8)?;
        self.write_byte_offset(length_index + 1, ((length >> 0) & 0xFF) as u8)?;

        // Pad to a multiple of 4 bytes
        let padding = (4 - length % 4) % 4;
        for _ in 0..padding {
            self.write_byte(0u8)?;
        }

        Ok(())
    }

    fn write_header(&mut self, header: &SctpHeader) -> Result<()> {
        self.write_be16(header.source_port)?;
        self.write_be16(header.destination_port)?;
        self.write_be32(header.verification_tag)?;
        self.write_be32(0)?; // checksum
        Ok(())
    }
}

pub struct WriterOwned {
    tlv_stack: Vec<usize>,
    data: Vec<u8>,
}

impl WriterOwned {
    pub fn new() -> WriterOwned {
        WriterOwned {
            data: Vec::<u8>::with_capacity(DEFAULT_MTU),
            tlv_stack: Vec::<usize>::with_capacity(4),
        }
    }
}

impl WriterOwned {
    pub fn to_owned(self) -> Vec<u8> {
        self.data
    }
}

impl Writer for WriterOwned {
    fn write_byte(&mut self, value: u8) -> Result<()> {
        self.data.push(value);
        Ok(())
    }
    fn write_bytes(&mut self, value: &[u8]) -> Result<()> {
        self.data.extend(value);
        Ok(())
    }
    fn write_byte_offset(&mut self, position: usize, value: u8) -> Result<()> {
        self.data[position] = value;
        Ok(())
    }
    fn len(&self) -> usize {
        return self.data.len();
    }
    fn mtu(&self) -> usize {
        return DEFAULT_MTU;
    }
    fn push_tlv(&mut self, position: usize) {
        self.tlv_stack.push(position);
    }
    fn pop_tlv(&mut self) -> Option<usize> {
        self.tlv_stack.pop()
    }
    fn write_chunk(&mut self, chunk_writer: &ChunkWriter) -> Result<()> {
        chunk_writer.write(self)
    }
    fn write_parameter(&mut self, parameter: &Parameter) -> Result<()> {
        write_parameter(self, parameter)
    }
    fn write_error_cause(&mut self, error_cause: &ErrorCause) -> Result<()> {
        write_error_cause(self, error_cause)
    }
    fn bytes(&mut self) -> Result<&[u8]> {
        if !self.tlv_stack.is_empty() {
            panic!("Imbalanced TLV on final serialization.");
        }
        Ok(&self.data[..])
    }
}

/*
 * NOTE: Other possible implementations might be:
 *   struct WriterBorrowedVec { }
 *   struct WriterSlice { }
 */
