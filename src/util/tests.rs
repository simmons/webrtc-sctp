//! Provide some test values for various data types

pub const BOOL_TEST_VALUES: &[bool] = &[true, false];
pub const U32_TEST_VALUES: &[u32] = &[
    0x00000000, 0x00000001, 0x00000002, 0x40404040, 0x7fffffff, 0x80000000, 0x80000001, 0xc0c0c0c0,
    0xfffffffd, 0xfffffffe, 0xffffffff,
];
pub const U16_TEST_VALUES: &[u16] = &[
    0x0000, 0x0001, 0x0002, 0x4040, 0x7fff, 0x8000, 0x8001, 0xc0c0, 0xfffd, 0xfffe, 0xffff,
];
pub const U8_TEST_VALUES: &[u8] = &[
    0x00, 0x01, 0x02, 0x40, 0x7f, 0x80, 0x81, 0xc0, 0xfd, 0xfe, 0xff,
];
pub const PAYLOAD_TEST_VALUES: &[&[u8]] = &[
    // no padding required
    b"",
    b"0123",
    b"01234567",
    b"0123456789ab",
    // 3 byte padding required
    b"x",
    b"0123x",
    b"01234567x",
    // 2 byte padding required
    b"xx",
    b"0123xx",
    b"01234567xx",
    // 1 byte padding required
    b"xxx",
    b"0123xxx",
    b"01234567xxx",
];

// Generate a list of Vec<u32>'s containing a range of test values for
// every vector size from 0 through the specified max_length.
pub fn u32_test_lists(max_length: usize) -> Vec<Vec<u32>> {
    let mut list = Vec::<Vec<u32>>::new();
    for length in 0..max_length {
        let combinations = U32_TEST_VALUES.len().pow(length as u32);
        for c in 0..combinations {
            let mut v = Vec::<u32>::with_capacity(length);
            for x in 0..length {
                let divisor = U32_TEST_VALUES.len().pow((length - x - 1) as u32);
                let idx = c / divisor % U32_TEST_VALUES.len();
                v.push(U32_TEST_VALUES[idx]);
            }
            list.push(v);
        }
    }
    list
}

// Generate a list of Vec<u16>'s containing a range of test values for
// every vector size from 0 through the specified max_length.
pub fn u16_test_lists(max_length: usize) -> Vec<Vec<u16>> {
    let mut list = Vec::<Vec<u16>>::new();
    for length in 0..max_length {
        let combinations = U16_TEST_VALUES.len().pow(length as u32);
        for c in 0..combinations {
            let mut v = Vec::<u16>::with_capacity(length);
            for x in 0..length {
                let divisor = U16_TEST_VALUES.len().pow((length - x - 1) as u32);
                let idx = c / divisor % U16_TEST_VALUES.len();
                v.push(U16_TEST_VALUES[idx]);
            }
            list.push(v);
        }
    }
    list
}

// Generate a list of Vec<u8>'s containing a range of test values for
// every vector size from 0 through the specified max_length.
pub fn u8_test_lists(max_length: usize) -> Vec<Vec<u8>> {
    let mut list = Vec::<Vec<u8>>::new();
    for length in 0..max_length {
        let combinations = U8_TEST_VALUES.len().pow(length as u32);
        for c in 0..combinations {
            let mut v = Vec::<u8>::with_capacity(length);
            for x in 0..length {
                let divisor = U8_TEST_VALUES.len().pow((length - x - 1) as u32);
                let idx = c / divisor % U8_TEST_VALUES.len();
                v.push(U8_TEST_VALUES[idx]);
            }
            list.push(v);
        }
    }
    list
}

use packet::chunk::DataChunk;
use packet::{SSN, TSN};
use rand::{self, Rng, RngCore, XorShiftRng};
use std::collections::HashMap;
use util::buffer::Buffer;
use Message;

fn deterministic_rng() -> XorShiftRng {
    const SEED: [u8; 16] = [
        0x04, 0xC1, 0x1D, 0xB7, 0x1E, 0xDC, 0x6F, 0x41, 0x74, 0x1B, 0x8C, 0xD7, 0x32, 0x58, 0x34,
        0x99,
    ];
    rand::SeedableRng::from_seed(SEED)
}

fn data_chunk(
    tsn: TSN,
    ssn: SSN,
    unordered: bool,
    beginning_fragment: bool,
    ending_fragment: bool,
    buffer: &[u8],
) -> DataChunk {
    DataChunk {
        unordered,
        beginning_fragment,
        ending_fragment,
        tsn,
        stream_id: 0,
        ssn,
        payload_protocol_id: 0,
        buffer: Buffer::new(buffer),
    }
}

pub struct TestData {
    pub chunks: Vec<DataChunk>,
    pub ordered_messages: Vec<Message>,
    pub unordered_messages: Vec<Message>,
}

pub fn generate_test_data(count: usize) -> TestData {
    let mut rng = deterministic_rng();

    let mut chunks = vec![];
    let mut ordered_messages = vec![];
    let mut unordered_messages = vec![];

    let mut tsn = TSN::new(rng.gen());
    let mut ssn = SSN::new(0);
    let mut fragments = 0;
    let mut beginning = false;
    const BUFFER_SIZE: usize = 7;
    let mut buffer = [0; BUFFER_SIZE];
    let mut message_reference_chunk = None; // First chunk of a message
    let mut message_buffer = vec![];
    let mut unordered: bool = false;
    for i in 0..count {
        if fragments == 0 {
            // New message -- how many fragments should it be?
            // 30% chance of being single fragment; otherwise 1..(count/10).
            let remaining = count - i;
            if rng.next_u32() % 100 <= 30 {
                fragments = 1;
            } else {
                let ceiling = 1.max((count / 10).min(remaining));
                fragments = rng.next_u32() as usize % ceiling + 1
            }
            // 50% chance of being unordered
            unordered = rng.gen();
            beginning = true;
        }

        // Create the chunk
        rng.fill_bytes(&mut buffer);
        let chunk_ssn = if unordered { SSN::new(0) } else { ssn };
        let chunk = data_chunk(
            tsn,
            chunk_ssn,
            unordered,
            beginning,
            fragments == 1,
            &buffer,
        );
        if beginning {
            message_reference_chunk = Some(chunk.clone());
        }
        chunks.push(chunk);
        message_buffer.extend_from_slice(&buffer);

        // Prepare for next chunk.
        beginning = false;
        fragments -= 1;
        if fragments == 0 {
            // Last fragment in message
            let message = Message::from_reference_chunk_and_buffer(
                &message_reference_chunk.take().unwrap(),
                &message_buffer,
            );
            if message.unordered {
                unordered_messages.push(message);
            } else {
                ordered_messages.push(message);
                ssn.incr();
            }
            message_buffer = vec![];
        }
        tsn.incr();
    }
    TestData {
        chunks,
        ordered_messages,
        unordered_messages,
    }
}

#[test]
pub fn test_generate_test_data() -> () {
    let TestData {
        chunks,
        ordered_messages,
        mut unordered_messages,
    } = generate_test_data(8192);

    // Create a HashMap of unordered messages keyed on their reference TSN.
    let unordered_map: HashMap<TSN, Message> =
        unordered_messages.drain(..).map(|m| (m.tsn, m)).collect();

    let mut ssn = 0;
    let mut message_reference_chunk = None;
    let mut message_buffer = vec![];
    for c in chunks.iter() {
        info!(
            "DATA tsn={} ssn={} U={} B={} E={}",
            c.tsn, c.ssn, c.unordered, c.beginning_fragment, c.ending_fragment
        );

        assert_eq!(c.beginning_fragment, message_reference_chunk.is_none());
        if c.beginning_fragment {
            assert!(message_buffer.is_empty());
            message_reference_chunk = Some(c.clone());
        }

        message_buffer.extend_from_slice(&c.buffer);

        if c.ending_fragment {
            let m;
            let r = &message_reference_chunk.unwrap();
            if !c.unordered {
                m = &ordered_messages[ssn];
                assert!(r.ssn.0 as usize == ssn);
                ssn += 1;
            } else {
                m = &unordered_map[&r.tsn];
                assert_eq!(r.ssn.0, 0);
            }
            assert!(r.unordered == m.unordered);
            assert!(r.stream_id == m.stream_id);
            assert!(r.ssn == m.ssn);
            assert!(r.payload_protocol_id == m.payload_protocol_id);
            assert!(&message_buffer[..] == &m.buffer[..]);
            message_reference_chunk = None;
            message_buffer.clear();
        }
    }
}

const REORDER_CHANCE: u32 = 15;
const REORDER_MIN_SHIFT: isize = -64;
const REORDER_MAX_SHIFT: isize = 256;
const DUP_CHANCE: u32 = 15;
const DUP_MIN_SHIFT: isize = -64;
const DUP_MAX_SHIFT: isize = 256;

fn reorder(rng: &mut XorShiftRng, chunks: &mut Vec<DataChunk>) {
    for i in 0..chunks.len() {
        if rng.gen::<u32>() % 100 < REORDER_CHANCE {
            let shift =
                rng.gen::<isize>() % (REORDER_MAX_SHIFT - REORDER_MIN_SHIFT) + REORDER_MIN_SHIFT;
            let position = i as isize - shift;
            if position >= 0 && position < chunks.len() as isize {
                let position = position as usize;
                chunks.swap(i, position);
            }
        }
    }
}

fn add_dups(rng: &mut XorShiftRng, chunks: &mut Vec<DataChunk>) {
    for i in 0..chunks.len() {
        if rng.gen::<u32>() % 100 < DUP_CHANCE {
            let shift = rng.gen::<isize>() % (DUP_MAX_SHIFT - DUP_MIN_SHIFT) + DUP_MIN_SHIFT;
            let position = i as isize - shift;
            if position >= 0 && position < chunks.len() as isize {
                let position = position as usize;
                let duplicate = chunks[i].clone();
                chunks.insert(position, duplicate);
            }
        }
    }
}

pub fn generate_shuffled_test_data(count: usize) -> TestData {
    let mut rng = deterministic_rng();
    let mut test_data = generate_test_data(count);
    reorder(&mut rng, &mut test_data.chunks);
    add_dups(&mut rng, &mut test_data.chunks);
    test_data
}
