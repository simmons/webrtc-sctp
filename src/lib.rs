extern crate crc;
#[macro_use]
extern crate nom;
extern crate blake2;
extern crate byteorder;
extern crate bytes;
extern crate futures;
extern crate rand;
extern crate time;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;
#[macro_use]
extern crate log;

pub mod error;
pub mod packet;
pub mod stack;
pub mod util;

use std::collections::LinkedList;
use std::fmt;

use packet::chunk::DataChunk;
use packet::{SSN, TSN};
use util::buffer::Buffer;

/// A message in SCTP is the basic unit of data used by the upper-layer protocol, and is split over
/// one or more DATA chunks for transmission.
#[derive(Clone, PartialEq)]
pub struct Message {
    pub tsn: TSN, // reference TSN -- the TSN of the first chunk of this message
    pub unordered: bool,
    pub stream_id: u16,
    pub ssn: SSN,
    pub payload_protocol_id: u32,
    pub buffer: Buffer,
}

impl Message {
    fn from_single_data_chunk(chunk: DataChunk) -> Message {
        assert!(chunk.beginning_fragment);
        assert!(chunk.ending_fragment);
        Message {
            tsn: chunk.tsn,
            unordered: chunk.unordered,
            stream_id: chunk.stream_id,
            ssn: chunk.ssn,
            payload_protocol_id: chunk.payload_protocol_id,
            buffer: chunk.buffer,
        }
    }

    fn from_data_chunk_list(mut chunks: LinkedList<DataChunk>) -> Message {
        let mut message = match chunks.front() {
            None => panic!("attempt to create message from zero chunks"),
            Some(c) => Message {
                tsn: c.tsn,
                unordered: c.unordered,
                stream_id: c.stream_id,
                ssn: c.ssn,
                payload_protocol_id: c.payload_protocol_id,
                buffer: c.buffer.clone(),
            },
        };

        // Build a flattened buffer from the chunks
        let mut vec = Vec::<u8>::new();
        while let Some(c) = chunks.pop_front() {
            vec.extend_from_slice(&c.buffer);
        }
        let mut buffer = Buffer::from_vec(vec);
        buffer.track_same_as(&message.buffer);
        std::mem::swap(&mut message.buffer, &mut buffer);

        message
    }

    fn from_chunks<'a, I>(chunks: I) -> Message
    where
        I: IntoIterator<Item = &'a DataChunk>,
    {
        let mut chunks = chunks.into_iter().peekable();
        let (tsn, unordered, stream_id, ssn, payload_protocol_id, tracker) = {
            let reference_chunk = chunks.peek().unwrap();
            (
                reference_chunk.tsn,
                reference_chunk.unordered,
                reference_chunk.stream_id,
                reference_chunk.ssn,
                reference_chunk.payload_protocol_id,
                reference_chunk.buffer.tracker(),
            )
        };

        // Build a flattened buffer from the chunks
        let mut vec = Vec::<u8>::new();
        for c in chunks {
            vec.extend_from_slice(&c.buffer);
        }
        let mut buffer = Buffer::from_vec(vec);
        if let Some(tracker) = tracker {
            buffer.track(&tracker);
        }

        Message {
            tsn,
            unordered,
            stream_id,
            ssn,
            payload_protocol_id,
            buffer: buffer,
        }
    }

    /// Create a Message from a reference data chunk and a combined buffer.  This is
    /// meant to be used for testing purposes.
    #[cfg(test)]
    fn from_reference_chunk_and_buffer(reference_chunk: &DataChunk, buffer: &[u8]) -> Message {
        Message {
            tsn: reference_chunk.tsn,
            unordered: reference_chunk.unordered,
            stream_id: reference_chunk.stream_id,
            ssn: reference_chunk.ssn,
            payload_protocol_id: reference_chunk.payload_protocol_id,
            buffer: Buffer::new(buffer),
        }
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "MSG tsn={} stream_id={} ssn={} ppi={} U={} len={}",
            self.tsn,
            self.stream_id,
            self.ssn,
            self.payload_protocol_id,
            if self.unordered { '1' } else { '0' },
            self.buffer.len()
        )
    }
}

/// A UserMessage represents a message that has been provided to (or is being provided by) the
/// upper-layer protocol.  The only difference between this and message is that a UserMessage
/// doesn't track its payload in a Buffer.
/// TODO: This is awkward.  We should find some way to use the same struct for both purposes, even
/// if it means exposing the user to Buffer.
#[derive(Clone, PartialEq)]
pub struct UserMessage {
    pub tsn: TSN, // reference TSN -- the TSN of the first chunk of this message
    pub unordered: bool,
    pub stream_id: u16,
    pub ssn: SSN,
    pub payload_protocol_id: u32,
    pub buffer: Vec<u8>,
}

impl UserMessage {
    pub fn new(
        unordered: bool,
        stream_id: u16,
        payload_protocol_id: u32,
        buffer: Vec<u8>,
    ) -> UserMessage {
        UserMessage {
            tsn: TSN::new(0),
            unordered,
            stream_id,
            ssn: SSN::new(0),
            payload_protocol_id,
            buffer,
        }
    }

    fn from_message(message: Message) -> UserMessage {
        UserMessage {
            tsn: message.tsn,
            unordered: message.unordered,
            stream_id: message.stream_id,
            ssn: message.ssn,
            payload_protocol_id: message.payload_protocol_id,
            buffer: message.buffer.to_vec(),
        }
    }
    fn to_message(&self) -> Message {
        Message {
            tsn: self.tsn,
            unordered: self.unordered,
            stream_id: self.stream_id,
            ssn: self.ssn,
            payload_protocol_id: self.payload_protocol_id,
            buffer: Buffer::new(&self.buffer[..]),
        }
    }
}

impl fmt::Debug for UserMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "MSG tsn={} stream_id={} ssn={} ppi={} U={} len={}",
            self.tsn,
            self.stream_id,
            self.ssn,
            self.payload_protocol_id,
            if self.unordered { '1' } else { '0' },
            self.buffer.len()
        )
    }
}
