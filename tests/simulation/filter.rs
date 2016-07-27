use super::{FlyingPacket, PacketStream};
use futures::{Async, Poll, Stream};
use rand::{Rng, XorShiftRng};

pub trait Filter: Stream<Item = FlyingPacket, Error = ()> + Send {
    fn set_incoming_stream(&mut self, stream: PacketStream);
}

pub type FilterBox = Box<Filter<Item = FlyingPacket, Error = ()> + Send>;

/*
 *
 * ===== DebugFilter =====
 *
 */

#[allow(unused)]
pub struct DebugFilter {
    incoming: Option<PacketStream>,
}

impl DebugFilter {
    #[allow(unused)]
    pub fn new() -> DebugFilter {
        DebugFilter { incoming: None }
    }
}

impl Filter for DebugFilter {
    fn set_incoming_stream(&mut self, stream: PacketStream) {
        self.incoming = Some(stream);
    }
}

impl Stream for DebugFilter {
    type Item = FlyingPacket;
    type Error = ();
    fn poll(&mut self) -> Poll<Option<FlyingPacket>, ()> {
        match self.incoming {
            Some(ref mut incoming) => match incoming.poll() {
                Ok(Async::Ready(Some(packet))) => {
                    println!(
                        "DEBUG_FILTER: {:?}->{:?} len={}",
                        packet.src,
                        packet.dst,
                        packet.llp.buffer.len()
                    );
                    Ok(Async::Ready(Some(packet)))
                }
                Ok(Async::Ready(None)) => Ok(Async::Ready(None)),
                Ok(Async::NotReady) => Ok(Async::NotReady),
                Err(e) => Err(e),
            },
            None => Ok(Async::NotReady),
        }
    }
}

/*
 *
 * ===== RandomDropFilter =====
 *
 */

#[allow(unused)]
pub struct RandomDropFilter {
    incoming: Option<PacketStream>,
    rng: XorShiftRng,
    drop_rate: u32,
    only_data: bool,
}

impl RandomDropFilter {
    #[allow(unused)]
    pub fn new(rng: &mut XorShiftRng, drop_percentage: f64, only_data: bool) -> RandomDropFilter {
        RandomDropFilter {
            incoming: None,
            rng: rng.clone(),
            drop_rate: (drop_percentage / 100.0 * (::std::u32::MAX as f64)) as u32,
            only_data,
        }
    }
}

impl Filter for RandomDropFilter {
    fn set_incoming_stream(&mut self, stream: PacketStream) {
        self.incoming = Some(stream);
    }
}

impl Stream for RandomDropFilter {
    type Item = FlyingPacket;
    type Error = ();
    fn poll(&mut self) -> Poll<Option<FlyingPacket>, ()> {
        match self.incoming {
            Some(ref mut incoming) => match incoming.poll() {
                Ok(Async::Ready(Some(packet))) => {
                    // Should we drop this packet?
                    if (!self.only_data || packet.is_data())
                        && self.rng.gen::<u32>() < self.drop_rate
                    {
                        // Drop.
                        Ok(Async::NotReady)
                    } else {
                        // Don't drop.
                        Ok(Async::Ready(Some(packet)))
                    }
                }
                Ok(Async::Ready(None)) => Ok(Async::Ready(None)),
                Ok(Async::NotReady) => Ok(Async::NotReady),
                Err(e) => Err(e),
            },
            None => Ok(Async::NotReady),
        }
    }
}

/*
 *
 * ===== NthDropFilter =====
 *
 */

#[allow(unused)]
pub struct NthDropFilter {
    incoming: Option<PacketStream>,
    nth: usize,
    count: usize,
}

impl NthDropFilter {
    /// nth is the packet to drop, starting with 1.
    #[allow(unused)]
    pub fn new(nth: usize) -> NthDropFilter {
        NthDropFilter {
            incoming: None,
            nth,
            count: 0,
        }
    }
}

impl Filter for NthDropFilter {
    fn set_incoming_stream(&mut self, stream: PacketStream) {
        self.incoming = Some(stream);
    }
}

impl Stream for NthDropFilter {
    type Item = FlyingPacket;
    type Error = ();
    fn poll(&mut self) -> Poll<Option<FlyingPacket>, ()> {
        match self.incoming {
            Some(ref mut incoming) => match incoming.poll() {
                Ok(Async::Ready(Some(packet))) => {
                    // Should we drop this packet?
                    if packet.is_data() {
                        self.count += 1;
                        if self.count == self.nth {
                            // Drop this data packet.

                            // When we drop a packet, we have to notify() or else we will never be
                            // polled again.
                            // TODO: Find out why this is.
                            ::futures::task::current().notify();

                            Ok(Async::NotReady)
                        } else {
                            // Don't drop this data packet.
                            Ok(Async::Ready(Some(packet)))
                        }
                    } else {
                        // Don't drop this non-data packet.
                        Ok(Async::Ready(Some(packet)))
                    }
                }
                Ok(Async::Ready(None)) => Ok(Async::Ready(None)),
                Ok(Async::NotReady) => Ok(Async::NotReady),
                Err(e) => Err(e),
            },
            None => Ok(Async::NotReady),
        }
    }
}
