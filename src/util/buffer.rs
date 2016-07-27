use std::cell::RefCell;
use std::cmp::PartialEq;
use std::fmt::{self, Debug, Formatter};
use std::ops::Deref;
use std::rc::Rc;

/// A Buffer wraps a Vec<u8> and provides a means of tracking the total byte usage of certain
/// classes of data.  This is used to determine our receiver window, among other things.
#[derive(Clone)]
pub struct Buffer {
    data: Rc<Vec<u8>>,
    tracker: Option<BufferTracker>,
}

impl Buffer {
    pub fn new(slice: &[u8]) -> Buffer {
        Buffer {
            data: Rc::new(slice.to_vec()),
            tracker: None,
        }
    }
    pub fn from_vec(vec: Vec<u8>) -> Buffer {
        Buffer {
            data: Rc::new(vec),
            tracker: None,
        }
    }
    pub fn empty() -> Buffer {
        Buffer {
            data: Rc::new(vec![]),
            tracker: None,
        }
    }
    pub fn track(&mut self, tracker: &BufferTracker) {
        // If this buffer is already being tracked, remove it from the previous tracking realm
        // before adding it to the new one.  This happens when buffers in the send_queue are moved
        // to the sent_queue.
        if let Some(ref mut existing_tracker) = self.tracker {
            existing_tracker.subtract(self.data.len());
        }
        tracker.add(self.data.len());
        self.tracker = Some(tracker.clone());
    }
    pub fn untrack(&mut self) {
        if let Some(tracker) = self.tracker.take() {
            tracker.subtract(self.data.len());
        }
    }
    pub fn track_same_as(&mut self, other: &Buffer) {
        if let Some(ref tracker) = other.tracker {
            self.track(tracker);
        }
    }
    pub fn tracker(&self) -> Option<BufferTracker> {
        if let Some(ref tracker) = self.tracker {
            Some(tracker.clone())
        } else {
            None
        }
    }
    pub fn to_vec(self) -> Vec<u8> {
        (&self.data[..]).to_vec()
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if Rc::strong_count(&self.data) == 1 {
            if let Some(ref tracker) = self.tracker {
                tracker.subtract(self.data.len());
            }
        }
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl Debug for Buffer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.data.fmt(f)
    }
}

impl PartialEq for Buffer {
    fn eq(&self, other: &Self) -> bool {
        (&*self.data).eq(&*other.data)
    }
}

#[derive(Clone)]
pub struct BufferTracker {
    inner: Rc<RefCell<Inner>>,
}

struct Inner {
    count: usize,
    bytes: usize,
}

impl BufferTracker {
    pub fn new() -> BufferTracker {
        BufferTracker {
            inner: Rc::new(RefCell::new(Inner { count: 0, bytes: 0 })),
        }
    }

    pub fn count(&self) -> usize {
        self.inner.borrow().count
    }

    pub fn bytes(&self) -> usize {
        self.inner.borrow().bytes
    }

    fn add(&self, bytes: usize) {
        let mut inner = self.inner.borrow_mut();
        inner.count += 1;
        inner.bytes += bytes;
    }

    fn subtract(&self, bytes: usize) {
        let mut inner = self.inner.borrow_mut();
        inner.count -= 1;
        inner.bytes -= bytes;
    }
}

impl Debug for BufferTracker {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "[c={},t={}]", self.count(), self.bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;

    const BUFFERS: usize = 8192;
    const MIN_BUFFER: usize = 1;
    const MAX_BUFFER: usize = 1500;
    const FILL_BYTE: u8 = 0xAA;

    fn make_buffer() -> Buffer {
        let len = rand::random::<usize>() % (MAX_BUFFER - MIN_BUFFER) + MIN_BUFFER;
        let mut vec = Vec::<u8>::with_capacity(len);
        vec.resize(len, FILL_BYTE);
        Buffer::new(&vec)
    }

    #[test]
    fn test_buffer() {
        let tracker = BufferTracker::new();
        {
            let mut buffers = Vec::<Buffer>::new();
            let mut count = 0usize;
            let mut bytes = 0usize;

            for _ in 0..BUFFERS {
                let mut buffer = make_buffer();
                count += 1;
                bytes += buffer.len();

                buffer.track(&tracker);
                buffers.push(buffer);

                assert_eq!(tracker.count(), count);
                assert_eq!(tracker.bytes(), bytes);
            }

            for _ in 0..BUFFERS {
                assert_eq!(tracker.count(), count);
                assert_eq!(tracker.bytes(), bytes);

                let index = rand::random::<usize>() % buffers.len();
                let buffer = buffers.remove(index);

                assert_eq!(tracker.count(), count);
                assert_eq!(tracker.bytes(), bytes);

                count -= 1;
                bytes -= buffer.len();
                // buffer is dropped here.
            }
        }
        assert_eq!(tracker.count(), 0);
        assert_eq!(tracker.bytes(), 0);
    }
}
