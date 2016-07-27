//! SCTP chunk parsing and synthesis.

use std::fmt;

use nom::{be_u16, be_u32, rest, IResult};

use packet::error_cause::*;
use packet::parameter::{parse_parameter, Parameter};
use packet::writer::{Result as WriterResult, Writer};
use packet::{SSN, TSN};
use util::buffer::Buffer;
use util::{hexdump, shorthash};

// Chunk types
const DATA_TYPE: u8 = 0;
const INIT_TYPE: u8 = 1;
const INITACK_TYPE: u8 = 2;
const SACK_TYPE: u8 = 3;
const HEARTBEAT_TYPE: u8 = 4;
const HEARTBEATACK_TYPE: u8 = 5;
const ABORT_TYPE: u8 = 6;
const SHUTDOWN_TYPE: u8 = 7;
const SHUTDOWNACK_TYPE: u8 = 8;
const ERROR_TYPE: u8 = 9;
const COOKIEECHO_TYPE: u8 = 10;
const COOKIEACK_TYPE: u8 = 11;
const SHUTDOWNCOMPLETE_TYPE: u8 = 14;

// TODO: The use of "Writer" is ambiguous.  A packet::writer::Writer
// provides an output channel and operations for writing certain data
// primitives to it, and a packet::chunk::ChunkWriter is a thing that
// uses that output channel as a destination for serializing chunks.  We
// need to shore up the terminology here.
pub trait ChunkWriter {
    fn write(&self, writer: &mut Writer) -> WriterResult<()>;
}

#[derive(Clone, PartialEq)]
pub enum Chunk {
    Data(DataChunk),
    Init(InitChunk),
    InitAck(InitAckChunk),
    Sack(SackChunk),
    Heartbeat(HeartbeatChunk),
    HeartbeatAck(HeartbeatAckChunk),
    Abort(AbortChunk),
    Shutdown(ShutdownChunk),
    ShutdownAck(ShutdownAckChunk),
    Error(ErrorChunk),
    CookieEcho(CookieEchoChunk),
    CookieAck(CookieAckChunk),
    ShutdownComplete(ShutdownCompleteChunk),
    Unknown(UnknownChunk),
}

impl Chunk {
    pub fn chunk_writer(&self) -> &ChunkWriter {
        match self {
            &Chunk::Data(ref c) => c,
            &Chunk::Init(ref c) => c,
            &Chunk::InitAck(ref c) => c,
            &Chunk::Sack(ref c) => c,
            &Chunk::Heartbeat(ref c) => c,
            &Chunk::HeartbeatAck(ref c) => c,
            &Chunk::Abort(ref c) => c,
            &Chunk::Shutdown(ref c) => c,
            &Chunk::ShutdownAck(ref c) => c,
            &Chunk::Error(ref c) => c,
            &Chunk::CookieEcho(ref c) => c,
            &Chunk::CookieAck(ref c) => c,
            &Chunk::ShutdownComplete(ref c) => c,
            &Chunk::Unknown(ref c) => c,
        }
    }
}

impl ChunkWriter for Chunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        self.chunk_writer().write(writer)
    }
}

impl fmt::Debug for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Chunk::Data(ref c) => c.fmt(f),
            &Chunk::Init(ref c) => c.fmt(f),
            &Chunk::InitAck(ref c) => c.fmt(f),
            &Chunk::Sack(ref c) => c.fmt(f),
            &Chunk::Heartbeat(ref c) => c.fmt(f),
            &Chunk::HeartbeatAck(ref c) => c.fmt(f),
            &Chunk::Abort(ref c) => c.fmt(f),
            &Chunk::Shutdown(ref c) => c.fmt(f),
            &Chunk::ShutdownAck(ref c) => c.fmt(f),
            &Chunk::Error(ref c) => c.fmt(f),
            &Chunk::CookieEcho(ref c) => c.fmt(f),
            &Chunk::CookieAck(ref c) => c.fmt(f),
            &Chunk::ShutdownComplete(ref c) => c.fmt(f),
            &Chunk::Unknown(ref c) => c.fmt(f),
        }
    }
}

macro_rules! chunk (
    ($name:ident<$otype:ty>, $submac:ident!( $($args:tt)* )) => {
        #[allow(unused_variables)]
        fn $name(flags: u8, i: &[u8]) -> ::nom::IResult<&[u8], $otype, u32> {
            #[allow(unused_macros)]
            macro_rules! flags (
                ($i:expr) => ({ Ok(($i, flags)) });
                ($i:expr,) => ({ flags!($i) });
            );
            $submac!(i, $($args)*)
        }
    };
);

// DATA Chunk

const DATA_FLAG_UNORDERED: u8 = 0x04;
const DATA_FLAG_BEGINNING_FRAGMENT: u8 = 0x02;
const DATA_FLAG_ENDING_FRAGMENT: u8 = 0x01;

#[derive(Clone, PartialEq)]
pub struct DataChunk {
    pub unordered: bool,
    pub beginning_fragment: bool,
    pub ending_fragment: bool,
    pub tsn: TSN,
    pub stream_id: u16,
    pub ssn: SSN,
    pub payload_protocol_id: u32,
    pub buffer: Buffer,
}

impl ChunkWriter for DataChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        let mut flags: u8 = 0;
        if self.unordered {
            flags |= DATA_FLAG_UNORDERED;
        }
        if self.beginning_fragment {
            flags |= DATA_FLAG_BEGINNING_FRAGMENT;
        }
        if self.ending_fragment {
            flags |= DATA_FLAG_ENDING_FRAGMENT
        }

        writer.open_tlv_chunk(DATA_TYPE, flags)?;
        writer.write_be32(self.tsn.0)?;
        writer.write_be16(self.stream_id)?;
        writer.write_be16(self.ssn.0)?;
        writer.write_be32(self.payload_protocol_id)?;
        writer.write_bytes(&self.buffer)?;
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for DataChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(
            f,
            "DATA tsn={} stream_id={} ssn={} UBE={}{}{} ppi={}",
            self.tsn,
            self.stream_id,
            self.ssn,
            if self.unordered { '1' } else { '0' },
            if self.beginning_fragment { '1' } else { '0' },
            if self.ending_fragment { '1' } else { '0' },
            self.payload_protocol_id
        ));
        hexdump(f, "\t", &self.buffer)
    }
}

chunk!(
    data_chunk<Chunk>,
    do_parse!(
        flags: flags!()
            >> tsn: be_u32
            >> stream_id: be_u16
            >> ssn: be_u16
            >> payload_protocol_id: be_u32
            >> buffer: rest
            >> ({
                Chunk::Data(DataChunk {
                    unordered: (flags & DATA_FLAG_UNORDERED) != 0,
                    beginning_fragment: (flags & DATA_FLAG_BEGINNING_FRAGMENT) != 0,
                    ending_fragment: (flags & DATA_FLAG_ENDING_FRAGMENT) != 0,
                    tsn: TSN::new(tsn),
                    stream_id: stream_id,
                    ssn: SSN::new(ssn),
                    payload_protocol_id: payload_protocol_id,
                    buffer: Buffer::new(buffer),
                })
            })
    )
);

// INIT Chunk

#[derive(Clone, PartialEq)]
pub struct InitChunk {
    pub initiate_tag: u32,
    pub a_rwnd: u32,
    pub num_outbound_streams: u16,
    pub num_inbound_streams: u16,
    pub initial_tsn: u32,
    pub parameters: Vec<Parameter>,
}

impl ChunkWriter for InitChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(INIT_TYPE, 0)?;
        writer.write_be32(self.initiate_tag)?;
        writer.write_be32(self.a_rwnd)?;
        writer.write_be16(self.num_outbound_streams)?;
        writer.write_be16(self.num_inbound_streams)?;
        writer.write_be32(self.initial_tsn)?;
        for parameter in &self.parameters {
            writer.write_parameter(parameter)?;
        }
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for InitChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(
            f,
            "INIT initiate_tag={} a_rwnd={} num_outbound_streams={} \
             num_inbound_streams={}, initial_tsn={}",
            self.initiate_tag,
            self.a_rwnd,
            self.num_outbound_streams,
            self.num_inbound_streams,
            self.initial_tsn
        ));
        for p in &self.parameters {
            try!(write!(f, "\n    {}", p));
        }
        Ok(())
    }
}

chunk!(
    init_chunk<Chunk>,
    do_parse!(
        initiate_tag: be_u32
            >> a_rwnd: be_u32
            >> num_outbound_streams: be_u16
            >> num_inbound_streams: be_u16
            >> initial_tsn: be_u32
            >> parameters: many0!(parse_parameter)
            >> (Chunk::Init(InitChunk {
                initiate_tag: initiate_tag,
                a_rwnd: a_rwnd,
                num_outbound_streams: num_outbound_streams,
                num_inbound_streams: num_inbound_streams,
                initial_tsn: initial_tsn,
                parameters: parameters,
            }))
    )
);

// INIT ACK Chunk

#[derive(Clone, PartialEq)]
pub struct InitAckChunk {
    pub initiate_tag: u32,
    pub a_rwnd: u32,
    pub num_outbound_streams: u16,
    pub num_inbound_streams: u16,
    pub initial_tsn: u32,
    pub parameters: Vec<Parameter>,
}

impl ChunkWriter for InitAckChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(INITACK_TYPE, 0)?;
        writer.write_be32(self.initiate_tag)?;
        writer.write_be32(self.a_rwnd)?;
        writer.write_be16(self.num_outbound_streams)?;
        writer.write_be16(self.num_inbound_streams)?;
        writer.write_be32(self.initial_tsn)?;
        for parameter in &self.parameters {
            writer.write_parameter(parameter)?;
        }
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for InitAckChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(
            f,
            "INIT ACK initiate_tag={} a_rwnd={} num_outbound_streams={} \
             num_inbound_streams={}, initial_tsn={}",
            self.initiate_tag,
            self.a_rwnd,
            self.num_outbound_streams,
            self.num_inbound_streams,
            self.initial_tsn
        ));
        for p in &self.parameters {
            try!(write!(f, "\n    {}", p));
        }
        Ok(())
    }
}

chunk!(
    initack_chunk<Chunk>,
    do_parse!(
        initiate_tag: be_u32
            >> a_rwnd: be_u32
            >> num_outbound_streams: be_u16
            >> num_inbound_streams: be_u16
            >> initial_tsn: be_u32
            >> parameters: many0!(parse_parameter)
            >> (Chunk::InitAck(InitAckChunk {
                initiate_tag: initiate_tag,
                a_rwnd: a_rwnd,
                num_outbound_streams: num_outbound_streams,
                num_inbound_streams: num_inbound_streams,
                initial_tsn: initial_tsn,
                parameters: parameters,
            }))
    )
);

// SACK Chunk

#[derive(Clone, PartialEq)]
pub struct GapAckBlock {
    pub start: u16,
    pub end: u16,
}

impl fmt::Debug for GapAckBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{},{}>", self.start, self.end)
    }
}

#[derive(Clone, PartialEq)]
pub struct SackChunk {
    pub cumulative_tsn_ack: TSN,
    pub a_rwnd: u32,
    pub gap_ack_blocks: Vec<GapAckBlock>,
    pub duplicate_tsns: Vec<TSN>,
}

impl ChunkWriter for SackChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(SACK_TYPE, 0)?;
        writer.write_be32(self.cumulative_tsn_ack.0)?;
        writer.write_be32(self.a_rwnd)?;
        writer.write_be16(self.gap_ack_blocks.len() as u16)?;
        writer.write_be16(self.duplicate_tsns.len() as u16)?;
        for gap_ack_block in &self.gap_ack_blocks {
            writer.write_be16(gap_ack_block.start)?;
            writer.write_be16(gap_ack_block.end)?;
        }
        for duplicate_tsn in &self.duplicate_tsns {
            writer.write_be32(duplicate_tsn.0)?;
        }
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for SackChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SACK cumulative_tsn_ack={} a_rwnd={} gap_acks:{:?} duplicate_tsns={:?}",
            self.cumulative_tsn_ack, self.a_rwnd, self.gap_ack_blocks, self.duplicate_tsns
        )
    }
}

named!(gap_ack_block<&[u8], GapAckBlock>, do_parse!(
    start:                  be_u16 >>
    end:                    be_u16 >>
    (
        GapAckBlock {
            start: start,
            end: end
        }
    )
));

chunk!(
    sack_chunk<Chunk>,
    do_parse!(
        cumulative_tsn_ack: be_u32
            >> a_rwnd: be_u32
            >> num_gap_ack_blocks: be_u16
            >> num_duplicate_tsns: be_u16
            >> gap_ack_blocks: count!(gap_ack_block, num_gap_ack_blocks as usize)
            >> duplicate_tsns: count!(be_u32, num_duplicate_tsns as usize)
            >> (Chunk::Sack(SackChunk {
                cumulative_tsn_ack: TSN::new(cumulative_tsn_ack),
                a_rwnd: a_rwnd,
                gap_ack_blocks: gap_ack_blocks,
                duplicate_tsns: duplicate_tsns.iter().map(|tsn| TSN::new(*tsn)).collect(),
            }))
    )
);

// HEARTBEAT Chunk

#[derive(Clone, PartialEq)]
pub struct HeartbeatChunk {
    pub parameter: Parameter,
}

impl ChunkWriter for HeartbeatChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(HEARTBEAT_TYPE, 0)?;
        writer.write_parameter(&self.parameter)?;
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for HeartbeatChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HEARTBEAT\n        {}", self.parameter)
    }
}

chunk!(
    heartbeat_chunk<Chunk>,
    do_parse!(
        parameter: parse_parameter
            >> (Chunk::Heartbeat(HeartbeatChunk {
                parameter: parameter,
            }))
    )
);

// HEARTBEAT ACK Chunk

#[derive(Clone, PartialEq)]
pub struct HeartbeatAckChunk {
    pub parameter: Parameter,
}

impl ChunkWriter for HeartbeatAckChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(HEARTBEATACK_TYPE, 0)?;
        writer.write_parameter(&self.parameter)?;
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for HeartbeatAckChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HEARTBEAT ACK\n        {}", self.parameter)
    }
}

chunk!(
    heartbeatack_chunk<Chunk>,
    do_parse!(
        parameter: parse_parameter
            >> (Chunk::HeartbeatAck(HeartbeatAckChunk {
                parameter: parameter,
            }))
    )
);

// ABORT Chunk

const ABORT_FLAG_VERIFICATION_TAG_REFLECTED: u8 = 0x01;

#[derive(Clone, PartialEq)]
pub struct AbortChunk {
    pub verification_tag_reflected: bool,
    pub error_causes: Vec<ErrorCause>,
}

impl ChunkWriter for AbortChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        let flags = if self.verification_tag_reflected {
            1
        } else {
            0
        };
        writer.open_tlv_chunk(ABORT_TYPE, flags)?;
        for error_cause in &self.error_causes {
            writer.write_error_cause(error_cause)?;
        }
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for AbortChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ABORT verification_tag_reflected={} error_causes:",
            self.verification_tag_reflected
        )?;
        for error_cause in &self.error_causes {
            write!(f, "{},", error_cause)?;
        }
        write!(f, "")
    }
}

chunk!(
    abort_chunk<Chunk>,
    do_parse!(
        flags: flags!()
            >> error_causes: many0!(parse_error_cause)
            >> (Chunk::Abort(AbortChunk {
                verification_tag_reflected: (flags & ABORT_FLAG_VERIFICATION_TAG_REFLECTED) != 0,
                error_causes: error_causes,
            }))
    )
);

// SHUTDOWN Chunk

#[derive(Clone, PartialEq)]
pub struct ShutdownChunk {
    pub cumulative_tsn_ack: TSN,
}

impl ChunkWriter for ShutdownChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(SHUTDOWN_TYPE, 0)?;
        writer.write_be32(self.cumulative_tsn_ack.0)?;
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for ShutdownChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SHUTDOWN cumulative_tsn_ack={}", self.cumulative_tsn_ack)
    }
}

chunk!(
    shutdown_chunk<Chunk>,
    do_parse!(
        cumulative_tsn_ack: be_u32
            >> (Chunk::Shutdown(ShutdownChunk {
                cumulative_tsn_ack: TSN::new(cumulative_tsn_ack),
            }))
    )
);

// SHUTDOWN ACK Chunk

#[derive(Clone, PartialEq)]
pub struct ShutdownAckChunk {}

impl ChunkWriter for ShutdownAckChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(SHUTDOWNACK_TYPE, 0)?;
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for ShutdownAckChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SHUTDOWN ACK")
    }
}

chunk!(
    shutdownack_chunk<Chunk>,
    do_parse!((Chunk::ShutdownAck(ShutdownAckChunk {})))
);

// ERROR Chunk

#[derive(Clone, PartialEq)]
pub struct ErrorChunk {
    pub error_causes: Vec<ErrorCause>,
}

impl ChunkWriter for ErrorChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(ERROR_TYPE, 0)?;
        for error_cause in &self.error_causes {
            writer.write_error_cause(error_cause)?;
        }
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for ErrorChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ERROR error_causes:")?;
        for error_cause in &self.error_causes {
            write!(f, "{},", error_cause)?;
        }
        write!(f, "")
    }
}

chunk!(
    error_chunk<Chunk>,
    do_parse!(
        error_causes: many0!(parse_error_cause) >> (Chunk::Error(ErrorChunk { error_causes }))
    )
);

// COOKIE ECHO Chunk

#[derive(Clone, PartialEq)]
pub struct CookieEchoChunk {
    pub cookie: Vec<u8>,
}

impl ChunkWriter for CookieEchoChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(COOKIEECHO_TYPE, 0)?;
        writer.write_bytes(&self.cookie)?;
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for CookieEchoChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // try!(writeln!(f, "COOKIE ECHO"));
        // hexdump(f, "\t", self.cookie.as_slice())
        write!(
            f,
            "COOKIE ECHO: {} ({} bytes)",
            shorthash(&self.cookie),
            self.cookie.len()
        )
    }
}

chunk!(
    cookieecho_chunk<Chunk>,
    do_parse!(
        cookie: rest
            >> (Chunk::CookieEcho(CookieEchoChunk {
                cookie: cookie.to_vec(),
            }))
    )
);

// COOKIE ACK Chunk

#[derive(Clone, PartialEq)]
pub struct CookieAckChunk {}

impl ChunkWriter for CookieAckChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(COOKIEACK_TYPE, 0)?;
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for CookieAckChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "COOKIE ACK")
    }
}

chunk!(
    cookieack_chunk<Chunk>,
    do_parse!((Chunk::CookieAck(CookieAckChunk {})))
);

// SHUTDOWN COMPLETE Chunk

const SHUTDOWN_COMPLETE_FLAG_VERIFICATION_TAG_REFLECTED: u8 = 0x01;

#[derive(Clone, PartialEq)]
pub struct ShutdownCompleteChunk {
    pub verification_tag_reflected: bool,
}

impl ChunkWriter for ShutdownCompleteChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        let flags: u8 = if self.verification_tag_reflected {
            SHUTDOWN_COMPLETE_FLAG_VERIFICATION_TAG_REFLECTED
        } else {
            0
        };
        writer.open_tlv_chunk(SHUTDOWNCOMPLETE_TYPE, flags)?;
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for ShutdownCompleteChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SHUTDOWN COMPLETE verification_tag_reflected={}",
            self.verification_tag_reflected
        )
    }
}

chunk!(
    shutdowncomplete_chunk<Chunk>,
    do_parse!(
        flags: flags!()
            >> (Chunk::ShutdownComplete(ShutdownCompleteChunk {
                verification_tag_reflected: (flags
                    & SHUTDOWN_COMPLETE_FLAG_VERIFICATION_TAG_REFLECTED)
                    != 0,
            }))
    )
);

// Unknown Chunk

#[derive(Clone, PartialEq)]
pub struct UnknownChunk {
    pub chunk_type: u8,
    pub chunk_flags: u8,
    pub data: Vec<u8>,
}

impl ChunkWriter for UnknownChunk {
    fn write(&self, writer: &mut Writer) -> WriterResult<()> {
        writer.open_tlv_chunk(self.chunk_type, self.chunk_flags)?;
        writer.write_bytes(&self.data)?;
        writer.close_tlv()?;
        Ok(())
    }
}

impl fmt::Debug for UnknownChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "UNKNOWN chunk type ({}) flags=0x{:x} length={} bytes",
            self.chunk_type,
            self.chunk_flags,
            self.data.len()
        )
    }
}

// TODO: Would it be faster to make this a macro?
#[inline]
fn chunk_dispatch(tag: u16, value: &[u8]) -> IResult<&[u8], Chunk> {
    let flags = (tag & 0xFF) as u8;
    let tag = (tag >> 8) as u8;
    let result = match tag {
        DATA_TYPE => data_chunk(flags, value),
        INIT_TYPE => init_chunk(flags, value),
        INITACK_TYPE => initack_chunk(flags, value),
        SACK_TYPE => sack_chunk(flags, value),
        HEARTBEAT_TYPE => heartbeat_chunk(flags, value),
        HEARTBEATACK_TYPE => heartbeatack_chunk(flags, value),
        ABORT_TYPE => abort_chunk(flags, value),
        SHUTDOWN_TYPE => shutdown_chunk(flags, value),
        SHUTDOWNACK_TYPE => shutdownack_chunk(flags, value),
        ERROR_TYPE => error_chunk(flags, value),
        COOKIEECHO_TYPE => cookieecho_chunk(flags, value),
        COOKIEACK_TYPE => cookieack_chunk(flags, value),
        SHUTDOWNCOMPLETE_TYPE => shutdowncomplete_chunk(flags, value),
        _ => Ok((
            &value[0..0],
            Chunk::Unknown(UnknownChunk {
                chunk_type: tag,
                chunk_flags: flags,
                data: value.to_vec(),
            }),
        )),
    };
    result
}

named!(pub parse_chunk<&[u8], Chunk >, do_parse!(
    chunk:  parse_tlv!(chunk_dispatch) >> ( chunk )
));

#[cfg(test)]
mod tests {
    use super::*;
    use packet::parameter;
    use packet::writer::*;
    use util::serial::Serial;
    use util::tests::*;

    /// How many trailing bytes cases should we test?
    const MAX_TRAILING_BYTES: usize = 5;

    /// Serialize a Chunk to a byte vector.
    fn serialize(chunk: &Chunk) -> Vec<u8> {
        let mut writer = WriterOwned::new();
        chunk.write(&mut writer).unwrap();
        writer.to_owned()
    }

    /// Perform basic chunk serialization and deserialization tests
    fn test_chunk(chunk: Chunk, expected_bytes: &[u8]) {
        // Test serialize
        let buffer = serialize(&chunk);
        assert_eq!(buffer, expected_bytes);

        // Test parsing
        let (remainder, parsed_chunk) = parse_chunk(&buffer).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(&parsed_chunk, &chunk);

        // Test serialization-deserialization with variable number of trailing bytes.
        test_chunk_serdes(&chunk);
    }

    /// Test serialization and deserialization of a particular chunk with
    /// a variable number of trailing bytes ranging from 0 to 4, inclusive.
    fn test_chunk_serdes(chunk: &Chunk) {
        for trailing_bytes in 0..MAX_TRAILING_BYTES {
            let mut buffer = serialize(&chunk);
            for _ in 0..trailing_bytes {
                buffer.push(0xa0);
            }
            let (remainder, parsed_chunk) = parse_chunk(&buffer).unwrap();
            assert_eq!(remainder.len(), trailing_bytes);
            assert_eq!(&parsed_chunk, chunk);
        }
    }

    // Test DATA Chunk

    fn data_chunk() -> DataChunk {
        DataChunk {
            unordered: true,
            beginning_fragment: true,
            ending_fragment: false,
            tsn: 0x00000101.into(),
            stream_id: 0x0001,
            ssn: SSN::new(0x0009),
            payload_protocol_id: 0x12345678,
            buffer: Buffer::new(b"This is a test."),
        }
    }

    const DATA_CHUNK_BYTES: &[u8] = &[
        0x00, 0x06, 0x00, 0x1f, 0x00, 0x00, 0x01, 0x01, // 0000: ........
        0x00, 0x01, 0x00, 0x09, 0x12, 0x34, 0x56, 0x78, // 0008: .....4Vx
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, // 0010: This is
        0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x00, // 0018: a test..
    ];

    /// Perform basic data chunk tests.
    #[test]
    fn test_data_chunk() {
        test_chunk(Chunk::Data(data_chunk()), DATA_CHUNK_BYTES);
    }

    /// Perform an full serialization-deserialization test of
    /// ~7.5M combinations of DataChunk field values.
    #[test]
    #[ignore]
    fn test_data_chunk_full() {
        // Exhaustive test.  ~7.5M iterations.
        for &unordered in BOOL_TEST_VALUES {
            for &beginning_fragment in BOOL_TEST_VALUES {
                for &ending_fragment in BOOL_TEST_VALUES {
                    for &tsn in U32_TEST_VALUES {
                        for &stream_id in U16_TEST_VALUES {
                            for &ssn in U16_TEST_VALUES {
                                for &payload_protocol_id in U32_TEST_VALUES {
                                    for data in PAYLOAD_TEST_VALUES {
                                        let chunk = DataChunk {
                                            unordered,
                                            beginning_fragment,
                                            ending_fragment,
                                            tsn: tsn.into(),
                                            stream_id,
                                            ssn: ssn.into(),
                                            payload_protocol_id,
                                            buffer: Buffer::new(*data),
                                        };
                                        test_chunk_serdes(&Chunk::Data(chunk.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Test INIT Chunk

    fn init_chunk() -> InitChunk {
        InitChunk {
            initiate_tag: 1780920053,
            a_rwnd: 106496,
            num_outbound_streams: 10,
            num_inbound_streams: 65535,
            initial_tsn: 2545339388,
            parameters: vec![
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[127, 0, 0, 1])),
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[10, 0, 2, 15])),
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[10, 10, 10, 101])),
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[172, 17, 0, 1])),
                Parameter::SupportedAddressTypes(vec![parameter::IPV4ADDRESS_TYPE]),
                Parameter::ECNCapable,
                Parameter::ForwardTSNSupported,
            ],
        }
    }

    const INIT_CHUNK_BYTES: &[u8] = &[
        0x01, 0x00, 0x00, 0x44, 0x6a, 0x26, 0xae, 0xf5, // 0000: ...Dj&..
        0x00, 0x01, 0xa0, 0x00, 0x00, 0x0a, 0xff, 0xff, // 0008: ........
        0x97, 0xb6, 0xcb, 0xfc, 0x00, 0x05, 0x00, 0x08, // 0010: ........
        0x7f, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00, 0x08, // 0018: ........
        0x0a, 0x00, 0x02, 0x0f, 0x00, 0x05, 0x00, 0x08, // 0020: ........
        0x0a, 0x0a, 0x0a, 0x65, 0x00, 0x05, 0x00, 0x08, // 0028: ...e....
        0xac, 0x11, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x06, // 0030: ........
        0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04, // 0038: ........
        0xc0, 0x00, 0x00, 0x04, // 0040: ....
    ];

    fn init_test_parameters() -> Vec<Vec<Parameter>> {
        vec![
            vec![
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[127, 0, 0, 1])),
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[10, 0, 2, 15])),
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[10, 10, 10, 101])),
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[172, 17, 0, 1])),
                Parameter::SupportedAddressTypes(vec![parameter::IPV4ADDRESS_TYPE]),
                Parameter::ECNCapable,
                Parameter::ForwardTSNSupported,
            ],
            vec![
                Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[127, 0, 0, 1])),
                Parameter::IPv6Address(parameter::IPv6Address::from_bytes(&[
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x5e, 0x60, 0xff, 0xfe,
                    0xeb, 0x23, 0x75,
                ])),
                Parameter::SupportedAddressTypes(vec![
                    parameter::IPV4ADDRESS_TYPE,
                    parameter::IPV6ADDRESS_TYPE,
                ]),
                Parameter::ECNCapable,
                Parameter::ForwardTSNSupported,
            ],
            vec![
                Parameter::IPv6Address(parameter::IPv6Address::from_bytes(&[
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x5e, 0x60, 0xff, 0xfe,
                    0xeb, 0x23, 0x75,
                ])),
                Parameter::SupportedAddressTypes(vec![parameter::IPV6ADDRESS_TYPE]),
            ],
            vec![
                Parameter::SupportedAddressTypes(vec![parameter::IPV4ADDRESS_TYPE]),
                Parameter::ECNCapable,
                Parameter::ForwardTSNSupported,
            ],
        ]
    }

    /// Perform basic init chunk tests.
    #[test]
    fn test_init_chunk() {
        test_chunk(Chunk::Init(init_chunk()), INIT_CHUNK_BYTES);
    }

    /// Perform an full serialization-deserialization test of
    /// 644,204 combinations of InitChunk field values.
    #[test]
    #[ignore]
    fn test_init_chunk_full() {
        for &initiate_tag in U32_TEST_VALUES {
            for &a_rwnd in U32_TEST_VALUES {
                for &num_outbound_streams in U16_TEST_VALUES {
                    for &num_inbound_streams in U16_TEST_VALUES {
                        for &initial_tsn in U32_TEST_VALUES {
                            for parameters in init_test_parameters() {
                                test_chunk_serdes(&Chunk::Init(InitChunk {
                                    initiate_tag,
                                    a_rwnd,
                                    num_outbound_streams,
                                    num_inbound_streams,
                                    initial_tsn,
                                    parameters,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // Test INIT ACK Chunk

    const INIT_ACK_STATE_COOKIE: &[u8] = &[
        0xf0, 0x5f, 0x15, 0x04, 0x5f, 0x05, 0xd8, 0x51, // 0000: ._.._..Q
        0xaa, 0xf3, 0x14, 0x2c, 0x37, 0xee, 0xab, 0xe8, // 0008: ...,7...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0010: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0018: ........
        0x00, 0x00, 0x00, 0x00, 0x05, 0x90, 0x45, 0xe6, // 0020: ......E.
        0x99, 0x88, 0xc9, 0xd9, 0x00, 0x00, 0x00, 0x00, // 0028: ........
        0x00, 0x00, 0x00, 0x00, 0x99, 0xe6, 0x01, 0x7a, // 0030: .......z
        0x04, 0x9f, 0xe1, 0x14, 0x0a, 0x00, 0x0a, 0x00, // 0038: ........
        0x53, 0x67, 0x54, 0xa2, 0x02, 0x00, 0x07, 0xe4, // 0040: SgT.....
        0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 0048: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0050: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0058: ........
        0xe4, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 0060: ........
        0x80, 0x02, 0x00, 0x24, 0x8d, 0x68, 0x80, 0xfc, // 0068: ...$.h..
        0xe1, 0x25, 0xf2, 0x6f, 0x5d, 0xf0, 0x3a, 0x14, // 0070: .%.o].:.
        0xa0, 0x06, 0x16, 0xa3, 0x91, 0x23, 0xce, 0x98, // 0078: .....#..
        0x84, 0xb6, 0xb0, 0x7b, 0x1f, 0x9c, 0x28, 0xeb, // 0080: ...{..(.
        0xb0, 0xee, 0x23, 0x50, 0x00, 0x00, 0x00, 0x00, // 0088: ..#P....
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0090: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0098: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00a0: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00a8: ........
        0x01, 0x00, 0x00, 0x24, 0xd9, 0xc9, 0x88, 0x99, // 00b0: ...$....
        0x00, 0x01, 0xa0, 0x00, 0x00, 0x0a, 0xff, 0xff, // 00b8: ........
        0x17, 0xeb, 0xe3, 0x26, 0x00, 0x0c, 0x00, 0x06, // 00c0: ...&....
        0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04, // 00c8: ........
        0xc0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // 00d0: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00d8: ........
        0x00, 0x00, 0x00, 0x00, // 00e0: ....
    ];

    fn init_ack_chunk() -> InitAckChunk {
        InitAckChunk {
            initiate_tag: 3863318533,
            a_rwnd: 106496,
            num_outbound_streams: 10,
            num_inbound_streams: 10,
            initial_tsn: 2723440467,
            parameters: vec![
                Parameter::StateCookie(INIT_ACK_STATE_COOKIE.to_owned()),
                Parameter::ECNCapable,
                Parameter::ForwardTSNSupported,
            ],
        }
    }

    const INIT_ACK_CHUNK_BYTES: &[u8] = &[
        0x02, 0x00, 0x01, 0x04, 0xe6, 0x45, 0x90, 0x05, // 0000: .....E..
        0x00, 0x01, 0xa0, 0x00, 0x00, 0x0a, 0x00, 0x0a, // 0008: ........
        0xa2, 0x54, 0x67, 0x53, 0x00, 0x07, 0x00, 0xe8, // 0010: .TgS....
        0xf0, 0x5f, 0x15, 0x04, 0x5f, 0x05, 0xd8, 0x51, // 0018: ._.._..Q
        0xaa, 0xf3, 0x14, 0x2c, 0x37, 0xee, 0xab, 0xe8, // 0020: ...,7...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0028: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0030: ........
        0x00, 0x00, 0x00, 0x00, 0x05, 0x90, 0x45, 0xe6, // 0038: ......E.
        0x99, 0x88, 0xc9, 0xd9, 0x00, 0x00, 0x00, 0x00, // 0040: ........
        0x00, 0x00, 0x00, 0x00, 0x99, 0xe6, 0x01, 0x7a, // 0048: .......z
        0x04, 0x9f, 0xe1, 0x14, 0x0a, 0x00, 0x0a, 0x00, // 0050: ........
        0x53, 0x67, 0x54, 0xa2, 0x02, 0x00, 0x07, 0xe4, // 0058: SgT.....
        0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 0060: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0068: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0070: ........
        0xe4, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 0078: ........
        0x80, 0x02, 0x00, 0x24, 0x8d, 0x68, 0x80, 0xfc, // 0080: ...$.h..
        0xe1, 0x25, 0xf2, 0x6f, 0x5d, 0xf0, 0x3a, 0x14, // 0088: .%.o].:.
        0xa0, 0x06, 0x16, 0xa3, 0x91, 0x23, 0xce, 0x98, // 0090: .....#..
        0x84, 0xb6, 0xb0, 0x7b, 0x1f, 0x9c, 0x28, 0xeb, // 0098: ...{..(.
        0xb0, 0xee, 0x23, 0x50, 0x00, 0x00, 0x00, 0x00, // 00a0: ..#P....
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00a8: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00b0: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00b8: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00c0: ........
        0x01, 0x00, 0x00, 0x24, 0xd9, 0xc9, 0x88, 0x99, // 00c8: ...$....
        0x00, 0x01, 0xa0, 0x00, 0x00, 0x0a, 0xff, 0xff, // 00d0: ........
        0x17, 0xeb, 0xe3, 0x26, 0x00, 0x0c, 0x00, 0x06, // 00d8: ...&....
        0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04, // 00e0: ........
        0xc0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // 00e8: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00f0: ........
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04, // 00f8: ........
        0xc0, 0x00, 0x00, 0x04, // 0100: ....
    ];

    fn init_ack_test_parameters() -> Vec<Vec<Parameter>> {
        vec![
            vec![
                Parameter::StateCookie(INIT_ACK_STATE_COOKIE.to_owned()),
                Parameter::ECNCapable,
                Parameter::ForwardTSNSupported,
            ],
            vec![
                Parameter::StateCookie(INIT_ACK_STATE_COOKIE.to_owned()),
                Parameter::UnrecognizedParameter(vec![0, 1, 2, 3]),
                Parameter::ECNCapable,
                Parameter::ForwardTSNSupported,
            ],
            vec![Parameter::StateCookie(INIT_ACK_STATE_COOKIE.to_owned())],
            vec![
                Parameter::StateCookie(INIT_ACK_STATE_COOKIE.to_owned()),
                Parameter::UnrecognizedParameter(vec![0, 1, 2, 3]),
            ],
        ]
    }

    /// Perform basic init ack chunk tests.
    #[test]
    fn test_init_ack_chunk() {
        test_chunk(Chunk::InitAck(init_ack_chunk()), INIT_ACK_CHUNK_BYTES);
    }

    /// Perform an full serialization-deserialization test of
    /// 644,204 combinations of InitAckChunk field values.
    #[test]
    #[ignore]
    fn test_init_ack_chunk_full() {
        for &initiate_tag in U32_TEST_VALUES {
            for &a_rwnd in U32_TEST_VALUES {
                for &num_outbound_streams in U16_TEST_VALUES {
                    for &num_inbound_streams in U16_TEST_VALUES {
                        for &initial_tsn in U32_TEST_VALUES {
                            for parameters in init_ack_test_parameters() {
                                test_chunk_serdes(&Chunk::InitAck(InitAckChunk {
                                    initiate_tag,
                                    a_rwnd,
                                    num_outbound_streams,
                                    num_inbound_streams,
                                    initial_tsn,
                                    parameters,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // Test SACK Chunk

    fn sack_chunk() -> SackChunk {
        SackChunk {
            cumulative_tsn_ack: TSN::new(401335079),
            a_rwnd: 106496,
            gap_ack_blocks: vec![],
            duplicate_tsns: vec![],
        }
    }

    const SACK_CHUNK_BYTES: &[u8] = &[
        0x03, 0x00, 0x00, 0x10, 0x17, 0xeb, 0xe3, 0x27, // 0000: .......'
        0x00, 0x01, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, // 0008: ........
    ];

    const SACK_MAX_GAP_LIST_SIZE: usize = 2;

    fn sack_test_gaps() -> Vec<Vec<GapAckBlock>> {
        let mut test_gaps = Vec::<Vec<GapAckBlock>>::new();
        for num_gaps in 0..SACK_MAX_GAP_LIST_SIZE {
            let combinations = U16_TEST_VALUES.len().pow((num_gaps as u32) * 2);
            for c in 0..combinations {
                let mut v = Vec::<GapAckBlock>::with_capacity(num_gaps);
                // start value iteration
                for x in 0..num_gaps {
                    let divisor = U16_TEST_VALUES.len().pow((num_gaps * 2 - x - 1) as u32);
                    let start_idx = c / divisor % U16_TEST_VALUES.len();

                    // end value iteration
                    for y in 0..num_gaps {
                        let divisor = U16_TEST_VALUES.len().pow((num_gaps - y - 1) as u32);
                        let end_idx = c / divisor % U16_TEST_VALUES.len();
                        let gap = GapAckBlock {
                            start: U16_TEST_VALUES[start_idx],
                            end: U16_TEST_VALUES[end_idx],
                        };
                        v.push(gap);
                    }
                }
                test_gaps.push(v);
            }
        }
        test_gaps
    }

    const SACK_MAX_DUP_LIST_SIZE: usize = 3;

    fn sack_test_dups() -> Vec<Vec<TSN>> {
        u32_test_lists(SACK_MAX_DUP_LIST_SIZE)
            .iter()
            .map(|list| list.iter().map(|tsn| TSN::new(*tsn)).collect())
            .collect()
    }

    /// Perform basic sack chunk tests.
    #[test]
    fn test_sack_chunk() {
        test_chunk(Chunk::Sack(sack_chunk()), SACK_CHUNK_BYTES);
    }

    /// Perform an full serialization-deserialization test of
    /// 1,963,346 combinations of SackChunk field values.
    #[test]
    #[ignore]
    fn test_sack_chunk_full() {
        for &cumulative_tsn_ack in U32_TEST_VALUES {
            for &a_rwnd in U32_TEST_VALUES {
                for gap_ack_blocks in sack_test_gaps() {
                    for duplicate_tsns in sack_test_dups() {
                        test_chunk_serdes(&Chunk::Sack(SackChunk {
                            cumulative_tsn_ack: TSN::new(cumulative_tsn_ack),
                            a_rwnd,
                            gap_ack_blocks: gap_ack_blocks.clone(),
                            duplicate_tsns,
                        }));
                    }
                }
            }
        }
    }

    // Test HEARTBEAT Chunk

    const HEARTBEAT_INFO: &[u8] = &[
        0x02, 0x00, 0x07, 0xe4, 0x0a, 0x0a, 0x0a, 0x65, // 0000: .......e
        0x70, 0x3a, 0x52, 0xd7, 0x00, 0x88, 0xff, 0xff, // 0008: p:R.....
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0010:  .......
        0x20, 0x00, 0x00, 0x00, 0x02, 0x99, 0x24, 0x00, // 0018:  .....$.
        0x01, 0x00, 0x00, 0x00, 0xf3, 0x83, 0xe1, 0x85, // 0020: ........
        0xa0, 0xa6, 0x76, 0xca, // 0028: ..v.
    ];

    fn heartbeat_chunk() -> HeartbeatChunk {
        HeartbeatChunk {
            parameter: Parameter::HeartbeatInfo(HEARTBEAT_INFO.to_vec()),
        }
    }

    const HEARTBEAT_CHUNK_BYTES: &[u8] = &[
        0x04, 0x00, 0x00, 0x34, 0x00, 0x01, 0x00, 0x30, // 0000: ...4...0
        0x02, 0x00, 0x07, 0xe4, 0x0a, 0x0a, 0x0a, 0x65, // 0008: .......e
        0x70, 0x3a, 0x52, 0xd7, 0x00, 0x88, 0xff, 0xff, // 0010: p:R.....
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0018:  .......
        0x20, 0x00, 0x00, 0x00, 0x02, 0x99, 0x24, 0x00, // 0020:  .....$.
        0x01, 0x00, 0x00, 0x00, 0xf3, 0x83, 0xe1, 0x85, // 0028: ........
        0xa0, 0xa6, 0x76, 0xca, // 0030: ..v.
    ];

    fn heartbeat_test_parameters() -> Vec<Parameter> {
        vec![
            Parameter::HeartbeatInfo(vec![]),
            Parameter::HeartbeatInfo(vec![0]),
            Parameter::HeartbeatInfo(vec![0, 1]),
            Parameter::HeartbeatInfo(vec![0, 1, 2]),
            Parameter::HeartbeatInfo(vec![0, 1, 2, 3]),
            Parameter::HeartbeatInfo(HEARTBEAT_CHUNK_BYTES.to_vec()),
        ]
    }

    /// Perform basic heartbeat chunk tests.
    #[test]
    fn test_heartbeat_chunk() {
        test_chunk(Chunk::Heartbeat(heartbeat_chunk()), HEARTBEAT_CHUNK_BYTES);
    }

    /// Perform an full serialization-deserialization test of
    /// 6 combinations of HeartbeatChunk field values.
    #[test]
    fn test_heartbeat_chunk_full() {
        for parameter in heartbeat_test_parameters() {
            test_chunk_serdes(&Chunk::Heartbeat(HeartbeatChunk { parameter }));
        }
    }

    // Test HEARTBEAT ACK Chunk

    fn heartbeat_ack_chunk() -> HeartbeatAckChunk {
        HeartbeatAckChunk {
            parameter: Parameter::HeartbeatInfo(HEARTBEAT_INFO.to_vec()),
        }
    }

    const HEARTBEAT_ACK_CHUNK_BYTES: &[u8] = &[
        0x05, 0x00, 0x00, 0x34, 0x00, 0x01, 0x00, 0x30, // 0000: ...4...0
        0x02, 0x00, 0x07, 0xe4, 0x0a, 0x0a, 0x0a, 0x65, // 0008: .......e
        0x70, 0x3a, 0x52, 0xd7, 0x00, 0x88, 0xff, 0xff, // 0010: p:R.....
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0018:  .......
        0x20, 0x00, 0x00, 0x00, 0x02, 0x99, 0x24, 0x00, // 0020:  .....$.
        0x01, 0x00, 0x00, 0x00, 0xf3, 0x83, 0xe1, 0x85, // 0028: ........
        0xa0, 0xa6, 0x76, 0xca, // 0030: ..v.
    ];

    /// Perform basic heartbeat ack chunk tests.
    #[test]
    fn test_heartbeat_ack_chunk() {
        test_chunk(
            Chunk::HeartbeatAck(heartbeat_ack_chunk()),
            HEARTBEAT_ACK_CHUNK_BYTES,
        );
    }

    /// Perform an full serialization-deserialization test of
    /// 6 combinations of HeartbeatAckChunk field values.
    #[test]
    fn test_heartbeat_ack_chunk_full() {
        for parameter in heartbeat_test_parameters() {
            test_chunk_serdes(&Chunk::HeartbeatAck(HeartbeatAckChunk { parameter }));
        }
    }

    // Test ABORT Chunk

    fn abort_chunk() -> AbortChunk {
        AbortChunk {
            verification_tag_reflected: false,
            error_causes: vec![],
        }
    }

    const ABORT_CHUNK_BYTES: &[u8] = &[
        0x06, 0x00, 0x00, 0x04, // 0000: ....
    ];

    fn error_causes() -> Vec<Vec<ErrorCause>> {
        vec![
            vec![],
            vec![ErrorCause::InvalidStreamIdentifier(0x42)],
            vec![ErrorCause::MissingMandatoryParameter(vec![
                parameter::IPV4ADDRESS_TYPE,
            ])],
            vec![ErrorCause::MissingMandatoryParameter(vec![
                parameter::IPV6ADDRESS_TYPE,
            ])],
            vec![
                ErrorCause::InvalidStreamIdentifier(0x42),
                ErrorCause::MissingMandatoryParameter(vec![
                    parameter::IPV4ADDRESS_TYPE,
                    parameter::IPV6ADDRESS_TYPE,
                ]),
            ],
            vec![
                ErrorCause::UnresolvableAddress(Parameter::IPv4Address(
                    parameter::IPv4Address::from_bytes(&[127, 0, 0, 1]),
                )),
                ErrorCause::RestartAssociationWithNewAddresses(vec![
                    Parameter::IPv4Address(parameter::IPv4Address::from_bytes(&[127, 0, 0, 1])),
                    Parameter::IPv6Address(parameter::IPv6Address::from_bytes(&[
                        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x5e, 0x60, 0xff,
                        0xfe, 0xeb, 0x23, 0x75,
                    ])),
                ]),
                ErrorCause::CookieReceivedWhileShuttingDown,
            ],
        ]
    }

    /// Perform basic abort chunk tests.
    #[test]
    fn test_abort_chunk() {
        test_chunk(Chunk::Abort(abort_chunk()), ABORT_CHUNK_BYTES);
    }

    /// Perform an full serialization-deserialization test of
    /// 12 combinations of AbortChunk field values.
    #[test]
    fn test_abort_chunk_full() {
        for &verification_tag_reflected in BOOL_TEST_VALUES {
            for error_causes in error_causes() {
                test_chunk_serdes(&Chunk::Abort(AbortChunk {
                    verification_tag_reflected,
                    error_causes,
                }));
            }
        }
    }

    // Test SHUTDOWN Chunk

    const SHUTDOWN_CHUNK: ShutdownChunk = ShutdownChunk {
        cumulative_tsn_ack: Serial(2723440466),
    };

    const SHUTDOWN_CHUNK_BYTES: &[u8] = &[
        0x07, 0x00, 0x00, 0x08, 0xa2, 0x54, 0x67, 0x52, // 0000: .....TgR
    ];

    /// Perform basic shutdown chunk tests.
    #[test]
    fn test_shutdown_chunk() {
        test_chunk(Chunk::Shutdown(SHUTDOWN_CHUNK), SHUTDOWN_CHUNK_BYTES);
    }

    /// Perform an full serialization-deserialization test of
    /// 11 combinations of ShutdownChunk field values.
    #[test]
    fn test_shutdown_chunk_full() {
        for &cumulative_tsn_ack in U32_TEST_VALUES {
            test_chunk_serdes(&Chunk::Shutdown(ShutdownChunk {
                cumulative_tsn_ack: TSN::new(cumulative_tsn_ack),
            }));
        }
    }

    // Test SHUTDOWN ACK Chunk

    const SHUTDOWN_ACK_CHUNK: ShutdownAckChunk = ShutdownAckChunk {};

    const SHUTDOWN_ACK_CHUNK_BYTES: &[u8] = &[
        0x08, 0x00, 0x00, 0x04, // 0000: ....
    ];

    /// Perform basic shutdown ack chunk tests.
    #[test]
    fn test_shutdown_ack_chunk() {
        test_chunk(
            Chunk::ShutdownAck(SHUTDOWN_ACK_CHUNK),
            SHUTDOWN_ACK_CHUNK_BYTES,
        );
    }

    // Test ERROR Chunk

    fn error_chunk() -> ErrorChunk {
        ErrorChunk {
            error_causes: vec![ErrorCause::InvalidStreamIdentifier(0x42)],
        }
    }

    const ERROR_CHUNK_BYTES: &[u8] = &[
        0x09, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x08, // 0000: ........
        0x00, 0x42, 0x00, 0x00, // 0008: .B..
    ];

    /// Perform basic error chunk tests.
    #[test]
    fn test_error_chunk() {
        test_chunk(Chunk::Error(error_chunk()), ERROR_CHUNK_BYTES);
    }

    /// Perform an full serialization-deserialization test of
    /// 6 combinations of ErrorChunk field values.
    #[test]
    fn test_error_chunk_full() {
        for error_causes in error_causes() {
            test_chunk_serdes(&Chunk::Error(ErrorChunk { error_causes }));
        }
    }

    // Test COOKIE ECHO Chunk

    const COOKIE: &[u8] = &[
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

    fn cookie_echo_chunk() -> CookieEchoChunk {
        CookieEchoChunk {
            cookie: COOKIE.to_vec(),
        }
    }

    const COOKIE_ECHO_CHUNK_BYTES: &[u8] = &[
        0x0a, 0x00, 0x01, 0x28, 0x9a, 0x92, 0x48, 0xf6, // 0000: ...(..H.
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

    /// Perform basic cookie echo chunk tests.
    #[test]
    fn test_cookie_echo_chunk() {
        test_chunk(
            Chunk::CookieEcho(cookie_echo_chunk()),
            COOKIE_ECHO_CHUNK_BYTES,
        );
    }

    // Test COOKIE ACK Chunk

    fn cookie_ack_chunk() -> CookieAckChunk {
        CookieAckChunk {}
    }

    const COOKIE_ACK_CHUNK_BYTES: &[u8] = &[
        0x0b, 0x00, 0x00, 0x04, // 0000: ....
    ];

    /// Perform basic cookie ack chunk tests.
    #[test]
    fn test_cookie_ack_chunk() {
        test_chunk(Chunk::CookieAck(cookie_ack_chunk()), COOKIE_ACK_CHUNK_BYTES);
    }

    // Test SHUTDOWN COMPLETE Chunk

    fn shutdown_complete_chunk() -> ShutdownCompleteChunk {
        ShutdownCompleteChunk {
            verification_tag_reflected: false,
        }
    }

    const SHUTDOWN_COMPLETE_CHUNK_BYTES: &[u8] = &[
        0x0e, 0x00, 0x00, 0x04, // 0000: ....
    ];

    /// Perform basic shutdown complete chunk tests.
    #[test]
    fn test_shutdown_complete_chunk() {
        test_chunk(
            Chunk::ShutdownComplete(shutdown_complete_chunk()),
            SHUTDOWN_COMPLETE_CHUNK_BYTES,
        );
    }

    /// Perform an full serialization-deserialization test of
    /// 2 combinations of ShutdownCompleteChunk field values.
    #[test]
    fn test_shutdown_complete_chunk_full() {
        for &verification_tag_reflected in BOOL_TEST_VALUES {
            test_chunk_serdes(&Chunk::ShutdownComplete(ShutdownCompleteChunk {
                verification_tag_reflected,
            }));
        }
    }
}
