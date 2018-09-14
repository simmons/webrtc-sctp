//! Queues
//!
//! Data received from an SCTP peer must be processed before being passed to the upper-layer
//! to perform out-of-order data reordering and message reassembly.  We provide specialized
//! queues in this module for performing these tasks.  An OrderedDataQueue processes ordered (U=0)
//! DATA chunks and yields SCTP messages in the correct sequence.  An UnorderedDataQueue processes
//! unordered (U=1) DATA chunks and yields messages as soon as they are available.  (Note that the
//! UnorderedDataQueue must still perform some ordering operations to arrange fragments in the
//! correct order, even if the yielded data is unordered at the message level.)
//!
//! When support for interleaved data (IDATA) is added, we will add OrderedIDataQueue and
//! UnorderedIDataQueue to allow ordering by the new Fragment Sequence Number (FSN) and Message
//! Identifier (MID) fields.

use std;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::BinaryHeap;
use std::collections::LinkedList;
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use error::{SctpError, SctpResult};
use packet::chunk::DataChunk;
use packet::{SSN, TSN};
use util::buffer::BufferTracker;
use util::serial::{Serial, SerialNumber};
use Message;

trait Numbered<T: SerialNumber>: Ord {
    fn number(&self) -> Serial<T>;
}

/// This is an adapter to provide numbering and ordering to DataChunk based on its TSN.  A
/// different adapter may be used for other numbering/ordering schemes, e.g.  based on stream id,
/// message id, fragment id, or some composite thereof.
#[derive(Clone, Debug)]
struct TsnNumberedDataChunk(DataChunk);

impl Numbered<u32> for TsnNumberedDataChunk {
    fn number(&self) -> Serial<u32> {
        self.0.tsn
    }
}

impl Ord for TsnNumberedDataChunk {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.tsn.cmp(&other.0.tsn)
    }
}

impl PartialOrd for TsnNumberedDataChunk {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TsnNumberedDataChunk {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for TsnNumberedDataChunk {}

impl std::borrow::Borrow<TSN> for TsnNumberedDataChunk {
    fn borrow(&self) -> &TSN {
        return &self.0.tsn;
    }
}

/// This reverses the ordering of a Numbered struct so that the Rust BinaryHeap max-heap can be
/// effectively turned into a min-heap.
struct InverseOrd<T: Numbered<S>, S: SerialNumber>(T, PhantomData<S>);

impl<T: Numbered<S>, S: SerialNumber> Ord for InverseOrd<T, S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0).reverse()
    }
}

impl<T: Numbered<S>, S: SerialNumber> PartialOrd for InverseOrd<T, S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Numbered<S>, S: SerialNumber> PartialEq for InverseOrd<T, S> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Numbered<S>, S: SerialNumber> Eq for InverseOrd<T, S> {}

pub enum FragmentOrderError {
    /// Our first chunk (after TSN sequencing) is not a beginning fragment.
    NoBeginning,
    /// A new beginning fragment was found before the previous message's end chunk.
    NoEnding,
}

/// This is the OrderedDataQueue.
/// Duplicates MUST be filtered out before chunks are fed to OrderedDataQueue.
/// Chunks fed to OrderedDataQueue MUST all have a common stream id.  (In other words,
/// streams must be demultiplexed and each stream fed to its own OrderedDataQueue.)
/// A HashMap+LinkedList implementation would perform only slightly better in the worst-case
/// scenarios, but this BinaryHeap+LinkedList implementation performs better across most cases.
pub struct OrderedDataQueue {
    heap: BinaryHeap<InverseOrd<TsnNumberedDataChunk, u32>>,
    list: LinkedList<DataChunk>,
    ssn: SSN,
}

impl OrderedDataQueue {
    /// Create a new OrderedDataQueue.
    pub fn new() -> OrderedDataQueue {
        let heap = BinaryHeap::<InverseOrd<TsnNumberedDataChunk, u32>>::new();
        let list = LinkedList::<DataChunk>::new();
        OrderedDataQueue {
            heap,
            list,
            ssn: Serial::<u16>::new(0),
        }
    }

    /// Enqueue chunks into the OrderedDataQueue, and return any messages that we have been able to
    /// assemble.
    pub fn enqueue(&mut self, chunk: DataChunk) -> SctpResult<Vec<Message>> {
        let chunk = TsnNumberedDataChunk(chunk);
        let mut messages: Vec<Message> = vec![];

        // Insert consecutive chunks onto the list, and non-consecutive chunks onto the heap.
        match self.list.back().map(|c| c.tsn) {
            None if chunk.0.ssn == self.ssn && chunk.0.beginning_fragment => {
                // The list is empty and this is the next expected chunk.
                // (A beginning fragment with the expected SSN.)
                if let Some(m) = self.push_consecutive(chunk.0)? {
                    messages.push(m);
                }
            }
            Some(back_tsn) if chunk.number() == back_tsn.next() => {
                if let Some(m) = self.push_consecutive(chunk.0)? {
                    messages.push(m);
                }
            }
            Some(back_tsn) if chunk.number() <= back_tsn => return Ok(messages), // duplicate
            _ => {
                self.heap.push(InverseOrd(chunk, PhantomData));
            }
        }

        // Harvest as we go.
        loop {
            let (heap_tsn, heap_ssn, heap_begin) = if let Some(c) = self.heap.peek() {
                ((c.0).0.tsn, (c.0).0.ssn, (c.0).0.beginning_fragment)
            } else {
                break;
            };

            // Is this the next expected chunk? (I.e., next SSN/B if list empty, or next TSN)
            let is_next = match self.list.back().map(|c| c.tsn) {
                None => heap_ssn == self.ssn && heap_begin,
                Some(back_tsn) => heap_tsn == back_tsn.next(),
            };

            if is_next {
                let chunk = self.heap.pop().unwrap().0;
                if let Some(m) = self.push_consecutive(chunk.0)? {
                    messages.push(m);
                }
            } else {
                break;
            }
        }
        Ok(messages)
    }

    /// Push consecutive chunks into the message reassembly list, and return any
    /// assembled message.
    fn push_consecutive(&mut self, chunk: DataChunk) -> SctpResult<Option<Message>> {
        // As an optimization for a common case, immediately return a message if this chunk is not
        // fragmented and no other message reassembly is in progress.
        if self.list.is_empty()
            && chunk.beginning_fragment
            && chunk.ending_fragment
            && chunk.ssn == self.ssn
        {
            self.ssn.incr();
            return Ok(Some(Message::from_single_data_chunk(chunk)));
        }

        // Confirm that this chunk is viable.
        // All messages must begin with a beginning fragment, must not contain a subsequent
        // beginning fragment, and have the same SSN for all fragments.
        // TODO: Proper error types
        match (self.list.is_empty(), chunk.beginning_fragment) {
            (true, false) => return Err(SctpError::ExpectedBeginningFragment),
            (false, true) => return Err(SctpError::UnexpectedBeginningFragment),
            _ => {
                if chunk.ssn != self.ssn {
                    // Assume messages must be delivered in order with respect to the TSN sequence.
                    // (Is this correct?)
                    return Err(SctpError::UnexpectedSSN);
                }
            }
        }
        let last_fragment: bool = chunk.ending_fragment;

        // Push this fragment
        self.list.push_back(chunk);

        // Do we have a complete message?
        if !last_fragment {
            return Ok(None);
        }

        // Convert the sequence of chunks into a message.
        let mut list = LinkedList::<DataChunk>::new();
        std::mem::swap(&mut self.list, &mut list);
        let message = Message::from_data_chunk_list(list);
        self.ssn.incr();
        Ok(Some(message))
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty() && self.heap.is_empty()
    }
}

impl Debug for OrderedDataQueue {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        //let mut last = self.start_tsn.previous();
        for ref c in &self.heap {
            //if c.0.number() != last.next() {
            //    write!(f, "*").unwrap();
            //}
            //last = c.0.number();
            write!(f, "{} ", c.0.number()).unwrap();
        }
        Ok(())
    }
}

pub struct UnorderedDataQueue {
    // TODO: This can be a BTreeSet now that TsnNumberedDataChunk implements Borrow<TSN>
    tree: BTreeMap<TSN, TsnNumberedDataChunk>,
}

impl UnorderedDataQueue {
    /// Create a new UnorderedDataQueue
    pub fn new() -> UnorderedDataQueue {
        let tree = BTreeMap::<TSN, TsnNumberedDataChunk>::new();
        UnorderedDataQueue { tree }
    }
    /// Enqueue chunks into the UnorderedDataQueue, and return any messages that we have been able
    /// to assemble.
    pub fn enqueue(&mut self, chunk: DataChunk) -> SctpResult<Option<Message>> {
        // Optimization: A one-fragment message can always be immediately delivered.
        if chunk.beginning_fragment && chunk.ending_fragment {
            return Ok(Some(Message::from_single_data_chunk(chunk)));
        }

        let new_tsn = chunk.tsn;
        self.tree.insert(new_tsn, TsnNumberedDataChunk(chunk));

        // scan forward (including the new chunk) for a consecutive ending fragment
        let mut expected_tsn = new_tsn;
        let mut end_tsn = None;
        for (tsn, ref chunk) in self.tree.range(new_tsn..) {
            if *tsn != expected_tsn {
                return Ok(None);
            } else if chunk.0.ending_fragment {
                end_tsn = Some(*tsn);
                break;
            }
            expected_tsn.incr();
        }
        let end_tsn = match end_tsn {
            None => return Ok(None),
            Some(tsn) => tsn,
        };

        // scan backwards (including the new chunk) for a consecutive beginning fragment
        let mut expected_tsn = new_tsn;
        let mut begin_tsn = None;

        for (tsn, ref chunk) in self.tree.range(..new_tsn.next()).rev() {
            if *tsn != expected_tsn {
                return Ok(None);
            } else if chunk.0.beginning_fragment {
                begin_tsn = Some(*tsn);
                break;
            }
            expected_tsn.decr();
        }
        let begin_tsn = match begin_tsn {
            None => return Ok(None),
            Some(tsn) => tsn,
        };

        // If this point is reached, then we have a complete fragment from
        // begin_tsn...end_tsn.
        let range = begin_tsn..end_tsn.next();

        // Assemble a message.
        let message = Message::from_chunks(self.tree.range(range).map(|(_, c)| &c.0 as &DataChunk));

        // Delete the fragments from the tree.
        // (It's a shame there's no remove_range() or similar.)
        // (It's also a shame we can't "for tsn in begin_tsn..end_tsn.next()", but TSN would need
        // to implement Step, and that's marked as "nightly-only experimental" in the docs.)
        let mut tsn = begin_tsn;
        while tsn < end_tsn.next() {
            // Remove this TSN from the tree.  It's a bug if the TSN isn't present.
            if self.tree.remove(&tsn).is_none() {
                panic!("could not remove TSN {} from tree", tsn);
            }
            tsn.incr();
        }

        Ok(Some(message))
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }
}

impl Debug for UnorderedDataQueue {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut last = TSN::new(0);
        for (_, ref c) in &self.tree {
            if c.0.tsn != last.next() {
                write!(f, "*").unwrap();
            }
            last = c.number();
            write!(
                f,
                "{}/{}{} ",
                c.0.tsn,
                if c.0.beginning_fragment { '1' } else { '0' },
                if c.0.ending_fragment { '1' } else { '0' },
            ).unwrap();
        }
        Ok(())
    }
}

/// An outgoing data queue suitable for use as a send-buffer (data chunks enqueued to be
/// transmitted) and a sent-buffer (data chunks that have been transmitted, but have not yet been
/// acknowledged).  This is currently implemented as a BTreeSet instead of a Vec to maintain
/// ordering even when retransmissions requirements might otherwise cause re-queueing in an
/// arbitrary order.  (Receiving multiple SACKs from the peer with different gap ack blocks could
/// lead to retransmissions in any conceivable order.)
///
/// This implementation should work, but it seems very inefficient.  It should definitely be
/// reassessed in the future to see if there is a more efficient strategy.
pub struct OutgoingDataQueue {
    set: BTreeSet<TsnNumberedDataChunk>,
    tracker: BufferTracker,
}

impl OutgoingDataQueue {
    /// Create a new OutgoingDataQueue
    pub fn new() -> OutgoingDataQueue {
        OutgoingDataQueue {
            set: BTreeSet::new(),
            tracker: BufferTracker::new(),
        }
    }

    pub fn push(&mut self, mut chunk: DataChunk) {
        // This condition is only because tracking keeps the buffer's bytes even if the insert()
        // drops the chunk due to an existing chunk having the same TSN.  The buffer's internal Arc
        // has a reference count of 2 on drop, so it has another owner.  There's a bug here
        // somewhere.
        // TODO: Remove this conditional, fix the bug, and confirm tests pass.
        if !self.contains(chunk.tsn) {
            // Track this chunk's buffer
            chunk.buffer.track(&self.tracker);
            self.set.insert(TsnNumberedDataChunk(chunk));
        }
    }

    pub fn pop(&mut self) -> Option<DataChunk> {
        if let Some(tsn) = self.front().map(|c| c.tsn) {
            let mut chunk = self.set.take(&tsn).map(|c| c.0);
            if let Some(ref mut chunk) = chunk {
                // Remove tracking for this chunk
                chunk.buffer.untrack();
            }
            chunk
        } else {
            None
        }
    }

    pub fn front(&self) -> Option<&DataChunk> {
        self.set.iter().next().map(|c| &c.0)
    }

    pub fn back(&self) -> Option<&DataChunk> {
        self.set.iter().next_back().map(|c| &c.0)
    }

    pub fn contains(&self, tsn: TSN) -> bool {
        self.set.contains(&tsn)
    }

    pub fn get(&self, tsn: TSN) -> Option<&DataChunk> {
        self.set.get(&tsn).map(|c| &c.0)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Return the total number of bytes used by all the data chunk buffers contained in this
    /// queue.
    pub fn bytes(&self) -> usize {
        self.tracker.bytes()
    }

    /// When we receive a cumulative TSN acknowledgement, all chunks with this TSN and earlier
    /// should be dropped.  This is true not only for the sent-buffer, but also for the send-buffer
    /// since some of its items may be retransmissions.
    pub fn expunge(&mut self, cumulative_tsn_ack: TSN) {
        let mut tsn = match self.front() {
            Some(c) => c.tsn,
            None => return,
        };
        let last = match self.back() {
            Some(c) => c.tsn,
            // If there's a front, there's always a back.
            None => unreachable!(),
        };
        let last = cumulative_tsn_ack.min(last);
        while tsn <= last {
            self.set.remove(&tsn);
            tsn += 1;
        }
    }

    /// Transfer data chunks from one queue to another, returning the number of payload bytes
    /// transferred.
    pub fn transfer(&mut self, other: &mut OutgoingDataQueue, tsn: TSN) -> usize {
        if let Some(mut c) = self.set.take(&tsn) {
            c.0.buffer.track(&other.tracker); // Move tracking
            let bytes = c.0.buffer.len();
            other.set.insert(c);
            bytes
        } else {
            0
        }
    }

    /// Transfer all data chunks from one queue to another, returning the total number of payload
    /// bytes transferred.
    pub fn transfer_all(&mut self, other: &mut OutgoingDataQueue) -> usize {
        let mut bytes = 0;
        let set = ::std::mem::replace(&mut self.set, BTreeSet::new());
        for mut chunk in set {
            chunk.0.buffer.track(&other.tracker); // Move tracking
            bytes += chunk.0.buffer.len();
            other.set.insert(chunk);
        }
        bytes
    }

    /// Transfer a range of data chunks from one queue to another, returning the total number of
    /// payload bytes transferred.
    pub fn transfer_range(
        &mut self,
        other: &mut OutgoingDataQueue,
        first: TSN,
        last: TSN,
    ) -> usize {
        assert!(last >= first);
        let mut bytes = 0;
        let mut tsn = first;
        let back_tsn = match self.back() {
            Some(c) => c.tsn,
            None => return 0,
        };
        let last = last.min(back_tsn);
        while tsn <= last {
            bytes += self.transfer(other, tsn);
            tsn += 1;
        }
        bytes
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use util::buffer::Buffer;
    use util::tests::*;

    #[test]
    fn test_inverse_order() {
        let data_chunk_1 = DataChunk {
            unordered: false,
            beginning_fragment: true,
            ending_fragment: true,
            tsn: Serial(42u32),
            stream_id: 0,
            ssn: SSN::new(0),
            payload_protocol_id: 0,
            buffer: Buffer::new(b""),
        };

        let data_chunk_2 = DataChunk {
            unordered: false,
            beginning_fragment: true,
            ending_fragment: true,
            tsn: Serial(100u32),
            stream_id: 0,
            ssn: SSN::new(0),
            payload_protocol_id: 0,
            buffer: Buffer::new(b""),
        };

        assert!(data_chunk_1.tsn == data_chunk_1.tsn);
        assert!(data_chunk_2.tsn == data_chunk_2.tsn);
        assert!(data_chunk_1.tsn != data_chunk_2.tsn);
        assert!(data_chunk_1.tsn < data_chunk_2.tsn);
        assert!(data_chunk_2.tsn > data_chunk_1.tsn);

        let numbered_1 = TsnNumberedDataChunk(data_chunk_1);
        let numbered_2 = TsnNumberedDataChunk(data_chunk_2);

        assert!(numbered_1.number() == 42.into());
        assert!(numbered_2.number() == 100.into());
        assert!(numbered_1.number() == numbered_1.0.tsn);
        assert!(numbered_2.number() == numbered_2.0.tsn);
        assert!(numbered_1 == numbered_1);
        assert!(numbered_2 == numbered_2);
        assert!(numbered_1 != numbered_2);
        assert!(numbered_1 < numbered_2);
        assert!(numbered_2 > numbered_1);

        let inverse_1 = InverseOrd(numbered_1, PhantomData);
        let inverse_2 = InverseOrd(numbered_2, PhantomData);

        assert!(inverse_1.0.number() == 42.into());
        assert!(inverse_2.0.number() == 100.into());
        assert!(inverse_1.0.number() == (inverse_1.0).0.tsn);
        assert!(inverse_2.0.number() == (inverse_2.0).0.tsn);
        assert!(inverse_1 == inverse_1);
        assert!(inverse_2 == inverse_2);
        assert!(inverse_1 != inverse_2);
        assert!(inverse_1 > inverse_2);
        assert!(inverse_2 < inverse_1);
    }

    type Item = Serial<u32>;

    impl Numbered<u32> for Item {
        fn number(&self) -> Item {
            *self
        }
    }

    #[test]
    fn test_ordered_data_queue() {
        const CHUNK_COUNT: usize = 32768;
        let TestData {
            chunks,
            ordered_messages: expected_messages,
            unordered_messages: _,
        } = generate_shuffled_test_data(CHUNK_COUNT);
        assert!(chunks.len() >= CHUNK_COUNT);

        let mut seen_tsns = HashSet::new();
        let mut expected_messages = expected_messages.iter();
        let mut ssn = SSN::new(0);
        let mut queue = OrderedDataQueue::new();
        for chunk in chunks {
            // We must filter out duplicate TSNs before feeding to OrderedDataQueue.
            if seen_tsns.contains(&chunk.tsn) {
                continue;
            }
            seen_tsns.insert(chunk.tsn);

            // Filter out unordered messages
            if chunk.unordered {
                continue;
            }

            // Feed chunks to OrderedDataQueue and verify the returned messages.
            let messages = queue.enqueue(chunk).unwrap();
            for message in messages {
                let expected_message = expected_messages.next().unwrap();
                assert_eq!(message.unordered, expected_message.unordered);
                assert_eq!(message.stream_id, expected_message.stream_id);
                assert_eq!(message.ssn, expected_message.ssn);
                assert_eq!(
                    message.payload_protocol_id,
                    expected_message.payload_protocol_id
                );
                assert_eq!(&message.buffer[..], &expected_message.buffer[..]);
                assert_eq!(message.ssn, ssn);
                ssn.incr();
            }
        }
        assert!(queue.is_empty());
    }

    #[test]
    fn test_unordered_data_queue() {
        const CHUNK_COUNT: usize = 32768;
        let TestData {
            chunks,
            ordered_messages: _,
            unordered_messages: mut expected_messages,
        } = generate_shuffled_test_data(CHUNK_COUNT);
        assert!(chunks.len() >= CHUNK_COUNT);

        // Load all expected message information into a HashMap keyed on its reference TSN.
        // We'll remove items one at a time as they are made available from the UnorderedDataQueue.
        let mut expected_message_map: HashMap<TSN, Message> =
            expected_messages.drain(..).map(|x| (x.tsn, x)).collect();

        // Enqueue each chunk, and verify the yielded messages.
        let mut seen_tsns = HashSet::new();
        let mut queue = UnorderedDataQueue::new();
        for chunk in chunks {
            // We must filter out duplicate TSNs before feeding to UnorderedDataQueue.
            if seen_tsns.contains(&chunk.tsn) {
                continue;
            }
            seen_tsns.insert(chunk.tsn);

            // Filter out ordered messages
            if !chunk.unordered {
                continue;
            }

            // Feed chunks to UnorderedDataQueue and verify the returned messages.
            if let Some(message) = queue.enqueue(chunk).unwrap() {
                let expected_message = match expected_message_map.remove(&message.tsn) {
                    None => panic!(
                        "Dequeued unexpected message with reference TSN {}",
                        message.tsn
                    ),
                    Some(m) => m,
                };
                assert_eq!(message.unordered, expected_message.unordered);
                assert_eq!(message.stream_id, expected_message.stream_id);
                assert_eq!(message.ssn, expected_message.ssn);
                assert_eq!(
                    message.payload_protocol_id,
                    expected_message.payload_protocol_id
                );
                assert_eq!(&message.buffer[..], &expected_message.buffer[..]);
            }
        }
        assert!(queue.is_empty());
    }

    #[test]
    fn test_outgoing_data_queue() {
        const CHUNK_COUNT: usize = 32768;
        let TestData {
            chunks,
            ordered_messages: _,
            unordered_messages: _,
        } = generate_shuffled_test_data(CHUNK_COUNT);
        assert!(chunks.len() >= CHUNK_COUNT);
        let mut min = chunks.iter().map(|c| c.tsn).min().unwrap();
        let max = chunks.iter().map(|c| c.tsn).max().unwrap();

        let mut queue = OutgoingDataQueue::new();
        assert!(queue.is_empty());
        for chunk in chunks {
            queue.push(chunk);
        }
        assert!(!queue.is_empty());
        assert_eq!(queue.len(), CHUNK_COUNT);
        assert_eq!(
            queue.bytes(),
            queue.set.iter().map(|c| c.0.buffer.len()).sum()
        );
        assert_eq!(queue.front().unwrap().tsn, min);
        assert_eq!(queue.back().unwrap().tsn, max);
        assert!(queue.contains(min));
        assert!(queue.contains(max));
        assert!(!queue.contains(min - 1));
        assert!(!queue.contains(max + 1));
        assert!(queue.contains(min + 1));
        assert!(queue.contains(max - 1));
        assert_eq!(queue.pop().unwrap().tsn, min);
        min += 1;
        assert_eq!(queue.pop().unwrap().tsn, min);
        min += 1;
        queue.expunge(min - 1 + 10);
        min += 10;
        assert_eq!(queue.len(), CHUNK_COUNT - 12);

        let mut queue2 = OutgoingDataQueue::new();
        queue.transfer(&mut queue2, min);
        min += 1;
        assert_eq!(queue.front().unwrap().tsn, min);
        assert_eq!(queue.len(), CHUNK_COUNT - 13);
        assert_eq!(queue2.len(), 1);
        queue.transfer_range(&mut queue2, min, min + 500 - 1);
        min += 500;
        assert_eq!(queue.len(), CHUNK_COUNT - 513);
        assert_eq!(queue2.len(), 501);

        let q1bytes = queue.bytes();
        let q2bytes = queue2.bytes();
        let chunk_bytes = queue.front().unwrap().buffer.len();
        let bytes_transferred = queue.transfer(&mut queue2, min);
        min += 1;
        assert_eq!(bytes_transferred, chunk_bytes);
        assert_eq!(queue.bytes(), q1bytes - chunk_bytes);
        assert_eq!(queue2.bytes(), q2bytes + chunk_bytes);

        let mut chunk_bytes = 0;
        let mut tsn = min;
        while tsn <= min + 99 {
            chunk_bytes += queue.get(tsn).unwrap().buffer.len();
            tsn += 1;
        }
        let q1bytes = queue.bytes();
        let q2bytes = queue2.bytes();
        let bytes_transferred = queue.transfer_range(&mut queue2, min, min + 99);
        min += 100;
        assert_eq!(bytes_transferred, chunk_bytes);
        assert_eq!(queue.bytes(), q1bytes - chunk_bytes);
        assert_eq!(queue2.bytes(), q2bytes + chunk_bytes);

        let original_queue1_len = queue.len();
        let original_queue2_len = queue2.len();
        let original_queue1_bytes = queue.bytes();
        let original_queue2_bytes = queue2.bytes();
        queue.transfer_all(&mut queue2);
        assert!(queue.is_empty());
        assert_eq!(queue.bytes(), 0);
        assert!(!queue2.is_empty());
        assert_eq!(queue2.len(), original_queue1_len + original_queue2_len);
        assert_eq!(
            queue2.bytes(),
            original_queue1_bytes + original_queue2_bytes
        );
    }
}
