use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use packet::chunk::{DataChunk, GapAckBlock, SackChunk};
use packet::TSN;
use util::buffer::BufferTracker;

/// This tuple struct represents an range of TSNs and is inclusive on both the beginning and the
/// end.  In other words, (20,22) includes TSNs 20, 21, and 22, and (30,30) represents a single TSN
/// of 30.  We define an equality and ordering for this type which is not valid in the general
/// sense, but only when the following constraints are observed:
/// 1. The first field must always be equal or less than the second field.
/// 2. Overlapping ranges are considered equal.  (This allows us to easily find a TSN's matching
///    range in a BTreeSet via contains().)
/// 3. Comparing overlapping ranges is not defined.
#[derive(Clone, Copy)]
struct TSNRange(TSN, TSN);

impl Ord for TSNRange {
    fn cmp(&self, other: &Self) -> Ordering {
        // Assumes a well-formed tuple range where TSNRange.0 <= TSNRange.1
        if self == other {
            Ordering::Equal
        } else if other.1 < self.0 {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }
}

impl PartialOrd for TSNRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TSNRange {
    fn eq(&self, other: &Self) -> bool {
        // Assumes a well-formed tuple range where TSNRange.0 <= TSNRange.1
        // In our range arithmetic, we're considering overlapped ranges to be equal.
        self.0 <= other.1 && other.0 <= self.1
    }
}

impl Eq for TSNRange {}

impl From<TSN> for TSNRange {
    fn from(tsn: TSN) -> TSNRange {
        TSNRange(tsn, tsn)
    }
}

impl TSNRange {
    #[allow(unused)]
    fn adjacent(&self, other: &Self) -> bool {
        self.1 == other.0.previous() || self.0 == other.1.next()
    }
    fn combine(&self, other: &Self) -> TSNRange {
        TSNRange(self.0.min(other.0), self.1.max(other.1))
    }
}

impl Debug for TSNRange {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.0, self.1)
    }
}

/// Track received TSNs and produce SACK chunks when needed.
/// This struct currently uses a BTreeSet to track gap ack blocks (non-consecutive TSN ranges),
/// which may be overkill for this application since the number of such blocks will likely be small
/// in the common case.  Realistically, we won't be able to report more than 368 gap blocks in a
/// SACK given an MTU of 1500, although we may internally track a much larger number.
///
/// TODO: Try implementations with Vec instead of BTreeSet to measure performance in common cases.
/// TODO: Consider limiting the number of gaps so a malicious peer can't exhaust our memory with a
/// carefully constructed series of discontinuous TSNs.  This may not be a problem, though, since
/// the receive window should naturally bound the size.
///
/// TODO: a_rwnd calculation
pub struct RecvTracker {
    cumulative_tsn: TSN,
    // "Gap" is unfortunate terminology, since it's really kind of the opposite -- an interval of
    // received TSNs after a gap.  But if it's good enough for RFC 4960, it's good enough for me.
    gaps: BTreeSet<TSNRange>,
    duplicates: Vec<TSN>,
    buffer_tracker: BufferTracker,
    initial_rwnd: u32,
}

impl RecvTracker {
    pub fn new(initial_tsn: TSN, initial_rwnd: u32) -> RecvTracker {
        RecvTracker {
            // "Cumulative TSN Ack: 32 bits (unsigned integer)
            // This parameter contains the TSN of the last DATA chunk received in
            // sequence before a gap.  In the case where no DATA chunk has been
            // received, this value is set to the peer's Initial TSN minus one."
            cumulative_tsn: initial_tsn - 1,
            gaps: BTreeSet::<TSNRange>::new(),
            duplicates: vec![],
            buffer_tracker: BufferTracker::new(),
            initial_rwnd,
        }
    }

    #[inline]
    pub fn buffer_tracker(&self) -> &BufferTracker {
        &self.buffer_tracker
    }

    /// Return false if this is a duplicate chunk.
    pub fn track(&mut self, data: &DataChunk) -> bool {
        self.insert(data.tsn)
    }

    fn insert(&mut self, tsn: TSN) -> bool {
        let tsn_range: TSNRange = tsn.into();
        if tsn <= self.cumulative_tsn {
            // This must be a duplicate TSN
            self.duplicates.push(tsn);
            return false;
        } else if tsn == self.cumulative_tsn.next() {
            // Is this TSN consecutive with the cumulative TSN?
            // Yes -- simply bump the cumulative TSN.
            // This is the ideal case which should be common in good network conditions.
            self.cumulative_tsn.incr();

            // Gap maintenance: If the increased cumulative TSN is adjacent to the first gap block,
            // then we can remove block and raise the cumulative TSN accordingly.
            if let Some(r) = self.gaps.get(&(tsn + 1).into()).cloned() {
                // remove the overlapping range
                self.gaps.remove(&r);
                // raise the cumulative TSN
                self.cumulative_tsn = r.1;
            }
        } else if self.gaps.contains(&TSNRange(tsn, tsn)) {
            // Is this TSN contained within an existing gap block range?
            // Yes -- This is a duplicate TSN.
            self.duplicates.push(tsn);
            return false;
        } else {
            // We need to reflect this new TSN in the gap blocks.
            if self.gaps.contains(&tsn_range) {
                // An existing gap block covers this TSN -- nothing to do.
                return true;
            } else {
                // Combine the new TSN range with any adjacent ranges
                let mut new_range = tsn_range;
                if let Some(r) = self.gaps.get(&(tsn - 1).into()).cloned() {
                    self.gaps.remove(&r);
                    new_range = new_range.combine(&r);
                }
                if let Some(r) = self.gaps.get(&(tsn + 1).into()).cloned() {
                    self.gaps.remove(&r);
                    new_range = new_range.combine(&r);
                }

                // Insert the new range.
                self.gaps.insert(new_range);
            }
        }
        true
    }

    pub fn seen(&self, tsn: TSN) -> bool {
        if self.cumulative_tsn > tsn {
            true
        } else {
            self.gaps.contains(&TSNRange(tsn, tsn))
        }
    }

    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    pub fn rwnd(&self) -> u32 {
        let total_buffer_usage = self.buffer_tracker.bytes();
        if total_buffer_usage > ::std::u32::MAX as usize {
            return 0;
        }
        let total_buffer_usage = total_buffer_usage as u32;
        if total_buffer_usage < self.initial_rwnd {
            self.initial_rwnd - total_buffer_usage
        } else {
            0
        }
    }

    pub fn sack(&mut self) -> SackChunk {
        // Render our list of gap ack block TSN offsets that fit into the 2^16-1 range after the
        // cumulative TSN.
        let max_gap = self.cumulative_tsn + ::std::u16::MAX as u32;
        let gap_ack_blocks = self
            .gaps
            .iter()
            .filter_map(|range| {
                if range.1 <= max_gap && range.0 <= max_gap {
                    Some(GapAckBlock {
                        start: (range.0 - self.cumulative_tsn).0 as u16,
                        end: (range.1 - self.cumulative_tsn).0 as u16,
                    })
                } else {
                    None
                }
            }).collect();

        // Prepare the list of duplicate TSNs to provide, clearing our tracked list.
        let mut duplicate_tsns = vec![];
        ::std::mem::swap(&mut duplicate_tsns, &mut self.duplicates);

        SackChunk {
            cumulative_tsn_ack: self.cumulative_tsn,
            a_rwnd: self.rwnd(),
            gap_ack_blocks,
            duplicate_tsns,
        }
    }
}

impl Debug for RecvTracker {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "[cumulative={},gaps={:?},dups={:?}]",
            self.cumulative_tsn, self.gaps, self.duplicates
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;
    use util::buffer::Buffer;

    const INPUT_SIZE: usize = 8192;
    const REORDER_CHANCE: u32 = 15;
    const REORDER_MIN_SHIFT: isize = -64;
    const REORDER_MAX_SHIFT: isize = 256;
    const DUP_CHANCE: u32 = 15;
    const DUP_MIN_SHIFT: isize = -64;
    const DUP_MAX_SHIFT: isize = 256;

    fn generate_list(count: usize, initial_number: TSN) -> Vec<TSN> {
        let mut n = initial_number;
        let mut items: Vec<TSN> = vec![];
        for _ in 0..count {
            items.push(n);
            n.incr();
        }
        items
    }

    fn reorder(items: &mut Vec<TSN>) {
        for i in 0..items.len() {
            if rand::random::<u32>() % 100 < REORDER_CHANCE {
                let shift = rand::random::<isize>() % (REORDER_MAX_SHIFT - REORDER_MIN_SHIFT)
                    + REORDER_MIN_SHIFT;
                let position = i as isize - shift;
                if position >= 0 && position < items.len() as isize {
                    let position = position as usize;
                    items.swap(i, position);
                }
            }
        }
    }

    fn add_dups(items: &mut Vec<TSN>) -> Vec<TSN> {
        for i in 0..items.len() {
            if rand::random::<u32>() % 100 < DUP_CHANCE {
                let shift =
                    rand::random::<isize>() % (DUP_MAX_SHIFT - DUP_MIN_SHIFT) + DUP_MIN_SHIFT;
                let position = i as isize - shift;
                if position >= 0 && position < items.len() as isize {
                    let position = position as usize;
                    let duplicate = items[i].clone();
                    items.insert(position, duplicate);
                }
            }
        }

        // Return a list of the duplicates
        let mut seen = ::std::collections::HashSet::<TSN>::new();
        let mut duplicates = Vec::<TSN>::new();
        for item in items {
            if !seen.insert(*item) {
                duplicates.push(*item);
            }
        }
        duplicates
    }

    #[test]
    fn test_recvtracker_tsn_tracking() {
        let initial_number = TSN::new(rand::random::<u32>());
        let mut input = generate_list(INPUT_SIZE, initial_number);
        reorder(&mut input);
        let duplicates = add_dups(&mut input);
        let mut recv_tracker = RecvTracker::new(initial_number, 128 * 1024);
        for item in input {
            recv_tracker.insert(item);
        }
        assert!(recv_tracker.is_complete());
        assert!(recv_tracker.cumulative_tsn == initial_number + (INPUT_SIZE as u32) - 1);
        assert!(recv_tracker.duplicates == duplicates);
    }

    #[test]
    fn test_recvtracker_rwnd_tracking() {
        const INITIAL_RWND: u32 = 128 * 1024;
        const MIN_BUFFER: usize = 1;
        const MAX_BUFFER: usize = 1500;
        const FILL_BYTE: u8 = 0xAA;

        fn make_buffer() -> Buffer {
            let len = rand::random::<usize>() % (MAX_BUFFER - MIN_BUFFER) + MIN_BUFFER;
            let mut vec = Vec::<u8>::with_capacity(len);
            vec.resize(len, FILL_BYTE);
            Buffer::new(&vec)
        }

        let mut tracker = RecvTracker::new(0.into(), INITIAL_RWND);
        {
            let mut buffers = Vec::<Buffer>::new();
            let mut bytes = 0usize;

            while bytes < (INITIAL_RWND as usize) * 2 {
                let mut buffer = make_buffer();
                bytes += buffer.len();
                buffer.track(tracker.buffer_tracker());
                buffers.push(buffer);

                if bytes > (INITIAL_RWND as usize) {
                    // There may be situations where we use more than INITIAL_RWND
                    // of buffer space, but we can't let a_rwnd underflow.
                    assert_eq!(tracker.sack().a_rwnd, 0);
                } else {
                    assert_eq!(tracker.sack().a_rwnd, INITIAL_RWND - (bytes as u32));
                }
            }
        }
        assert_eq!(tracker.sack().a_rwnd, INITIAL_RWND);
    }
}
