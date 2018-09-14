//! The SCTP stack is implemented as a single future that can be provided to Tokio.  It delegates
//! internally to child futures (e.g. for associations).

pub mod association;
pub mod cookie;
pub mod lowerlayer;
pub mod queue;
pub mod recvtracker;
pub mod settings;
pub mod sync;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use futures::sync::mpsc;
use futures::sync::oneshot;
use futures::{self, Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use rand;
use tokio_core::reactor::Handle;
use tokio_timer;

use self::association::*;
use self::cookie::Secret;
use self::lowerlayer::{packet_to_lower_layer, LowerLayer, UdpLowerLayer};
use self::sync::SctpHandle;
use error::SctpResult;
use packet::chunk::Chunk;
use packet::{self, SctpPacket};

pub struct Packet {
    pub sctp_packet: SctpPacket,
    pub llp_address: SocketAddr,
}

#[derive(Debug, Clone)]
pub enum Timeout {
    None,
    Default,
    Some(Duration),
}
impl Timeout {
    fn timer(
        &self,
        timer: &tokio_timer::Timer,
        default: Option<Duration>,
    ) -> Option<tokio_timer::Sleep> {
        match self {
            &Timeout::None => None,
            &Timeout::Default => default.map(|d| timer.sleep(d)),
            &Timeout::Some(duration) => Some(timer.sleep(duration)),
        }
    }
    fn duration(&self, default: Option<Duration>) -> Option<Duration> {
        match self {
            &Timeout::None => None,
            &Timeout::Default => default,
            &Timeout::Some(duration) => Some(duration),
        }
    }
}

/// Resources shared by all associations in this stack.  Its members should be cloneable in a
/// lightweight fashion.
#[derive(Clone)]
pub struct StackResources {
    timer: tokio_timer::Timer,
    secret: Secret,
}

/// The state for the SCTP stack itself.
pub struct SctpStack {
    resources: StackResources,
    started: bool,
    command_tx: mpsc::Sender<SctpCommand>,
    command_rx: mpsc::Receiver<SctpCommand>,
    stack_accept_tx: mpsc::Sender<StackAcceptItem>,
    stack_accept_rx: mpsc::Receiver<StackAcceptItem>,
    // TODO: this could be changed to a VecDeque.
    outgoing_tx: mpsc::UnboundedSender<Packet>,
    outgoing_future: Box<Future<Item = (), Error = io::Error>>,
    incoming_stream: Box<Stream<Item = Packet, Error = io::Error>>,
    incoming_packet: Option<Packet>,
    associations: Vec<Association>,
    llp_listen_address: SocketAddr,
    next_ephemeral: u16,
}

#[derive(Debug)]
pub enum SctpCommand {
    Connect(
        SocketAddr,
        Timeout,
        oneshot::Sender<SctpResult<mpsc::Sender<AssociationCommand>>>,
    ),
    Listen(
        u16,
        oneshot::Sender<(AssociationCommandSender, AcceptQueueReceiver)>,
    ),
    Exit(oneshot::Sender<()>),
}

pub type SctpCommandTx = mpsc::Sender<SctpCommand>;

impl SctpStack {
    pub fn new(tokio: Handle) -> SctpStack {
        let lower_layer = UdpLowerLayer::new(tokio);
        Self::new_with_lower_layer(Box::new(lower_layer))
    }

    pub fn new_with_lower_layer(lower_layer: Box<LowerLayer>) -> SctpStack {
        let (command_tx, command_rx) = mpsc::channel::<SctpCommand>(0);
        let (stack_accept_tx, stack_accept_rx) =
            mpsc::channel::<StackAcceptItem>(DEFAULT_ACCEPT_QUEUE_SIZE);
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded::<Packet>();
        let llp_listen_address = lower_layer.address();
        let (lower_layer_sink, incoming_stream) = lower_layer.split();
        let timer = tokio_timer::Timer::default();
        let secret = Secret::new();

        // Connect our outgoing mpsc stream to the lower layer sink, mapping
        // SctpPacket data structures into byte buffers.
        let outgoing_future = Box::new(
            outgoing_rx
                .map(|packet| {
                    trace!("Outgoing SCTP packet: {:?}", packet.sctp_packet);
                    packet_to_lower_layer(&packet)
                })
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "outgoing"))
                .forward(lower_layer_sink)
                .map(|_| ()),
        );

        // Connect our incoming LLP stream to SCTP packet parsing
        let incoming_stream = incoming_stream.filter_map(|llp_packet| {
            match packet::parse(&llp_packet.buffer[0..llp_packet.length]) {
                Ok(p) => Some(Packet {
                    sctp_packet: p,
                    llp_address: llp_packet.address,
                }),
                Err(e) => {
                    warn!("malformed packet: {}", e);
                    None
                }
            }
        });

        SctpStack {
            resources: StackResources {
                timer: timer,
                secret: secret,
            },
            started: false,
            command_tx,
            command_rx,
            stack_accept_tx,
            stack_accept_rx,
            outgoing_tx,
            outgoing_future,
            incoming_stream: Box::new(incoming_stream),
            incoming_packet: None,
            associations: vec![],
            llp_listen_address,
            next_ephemeral: rand::random::<u16>(),
        }
    }

    pub fn handle(&self) -> SctpHandle {
        SctpHandle::new(self.command_tx.clone())
    }

    pub fn command_tx(&self) -> SctpCommandTx {
        self.command_tx.clone()
    }

    // The Internet Assigned Numbers Authority (IANA) suggests the range 49152 to 65535 (215+214 to
    // 216−1) for dynamic or private ports.[1]
    // https://tools.ietf.org/html/rfc6056
    fn ephemeral_port(&mut self) -> io::Result<u16> {
        // RFC 6056 section 3.3.5
        // "Algorithm 5: Random-Increments Port Selection Algorithm"
        const MIN_EPHEMERAL: u16 = 49152;
        const MAX_EPHEMERAL: u16 = 65535;
        const NUM_EPHEMERAL: u16 = MAX_EPHEMERAL - MIN_EPHEMERAL + 1;
        const TRADE_OFF: u16 = 500;

        let mut count = NUM_EPHEMERAL;
        loop {
            self.next_ephemeral = self
                .next_ephemeral
                .wrapping_add((rand::random::<u16>() % TRADE_OFF) + 1);
            let port = MIN_EPHEMERAL + (self.next_ephemeral % NUM_EPHEMERAL);

            let mut found: bool = false;
            for mut association in &self.associations {
                if association.network.local_port == port {
                    found = true;
                    break;
                }
            }
            if !found {
                return Ok(port);
            }

            count -= 1;
            if count == 0 {
                break;
            };
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "ephemeral ports exhausted",
        ))
    }

    // TODO: verify that an association matches the LLP source so that other processes on
    // the peer can't hijack the peer's SCTP association from a different UDP source port.

    fn lookup_association<'a>(
        &'a mut self,
        sctp_peer: SocketAddr,
        local_port: u16,
    ) -> Option<&'a mut Association> {
        for mut association in &mut self.associations {
            if association.network.sctp_peer == sctp_peer
                && association.network.local_port == local_port
            {
                return Some(association);
            }
        }
        None
    }

    fn association_exists(&self, sctp_peer: SocketAddr, local_port: u16) -> bool {
        for mut association in &self.associations {
            if association.network.sctp_peer == sctp_peer
                && association.network.local_port == local_port
            {
                return true;
            }
        }
        false
    }

    fn lookup_listening_association<'a>(
        &'a mut self,
        local_port: u16,
    ) -> Option<&'a mut Association> {
        for mut association in &mut self.associations {
            match association.state {
                AssociationState::Listen => {
                    if association.network.local_port == local_port {
                        return Some(association);
                    }
                }
                _ => {}
            }
        }
        None
    }

    // Lookup an association based on an incoming packet.
    fn lookup_association_by_packet<'a>(
        &'a mut self,
        packet: &Packet,
    ) -> Option<&'a mut Association> {
        fn is_init_packet(packet: &Packet) -> bool {
            packet.sctp_packet.chunks.len() == 1 && match packet.sctp_packet.chunks[0] {
                Chunk::Init(_) => true,
                _ => false,
            }
        }

        fn is_cookie_echo_packet(packet: &Packet) -> bool {
            packet
                .sctp_packet
                .chunks
                .iter()
                .find(|chunk| match chunk {
                    &&Chunk::CookieEcho(_) => true,
                    _ => false,
                }).is_some()
        }

        // Determine the SCTP peer, which may be different from the LLP peer.
        // (e.g. LLP peer may have the UDP-encaps port number.)
        let sctp_peer = SocketAddr::new(
            packet.llp_address.ip(),
            packet.sctp_packet.header.source_port,
        );

        if is_init_packet(packet) {
            // Note that we try to send INIT packets to regular associations, before
            // looking for listening associations.
            if self.association_exists(sctp_peer, packet.sctp_packet.header.destination_port) {
                self.lookup_association(sctp_peer, packet.sctp_packet.header.destination_port)
            } else {
                self.lookup_listening_association(packet.sctp_packet.header.destination_port)
            }
        } else if is_cookie_echo_packet(packet) {
            // Note that we try to send COOKIE ECHO packets to regular associations, before
            // looking for listening associations.
            if self.association_exists(sctp_peer, packet.sctp_packet.header.destination_port) {
                self.lookup_association(sctp_peer, packet.sctp_packet.header.destination_port)
            } else {
                self.lookup_listening_association(packet.sctp_packet.header.destination_port)
            }
        } else {
            self.lookup_association(sctp_peer, packet.sctp_packet.header.destination_port)
        }
    }

    // Send the provided packet to its association stream.
    fn send_to_association(&mut self, packet: Packet) -> StartSend<Packet, io::Error> {
        let association = self.lookup_association_by_packet(&packet);
        match association {
            Some(association) => association.start_send(packet),
            None => {
                warn!(
                    "OOTB: No association is valid for this packet: {:?}",
                    packet.sctp_packet
                );
                Ok(AsyncSink::Ready)
            }
        }
    }
}

impl Future for SctpStack {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        // If this is the first poll...
        if !self.started {
            // TODO: We're not doing anything with this... remove?
            self.started = true;
        }

        // Poll the outgoing future
        // TODO: handle Ready (close stack?)
        self.outgoing_future.poll()?;

        // Poll incoming commands
        if let Ok(Async::Ready(Some(command))) = self.command_rx.poll() {
            use self::SctpCommand::*;
            match command {
                Connect(mut destination, timeout, return_tx) => {
                    // TODO: We shouldn't have to deal with LLP concerns here.  Some LLPs won't
                    // even have the concept of a destination.  For example, when DTLS is the lower
                    // layer, there is only us and the peer.  Should SctpStack be generic over an
                    // LLP, so per-stack and per-association LLP parameters only include what is
                    // needed?
                    let llp_destination = SocketAddr::new(
                        destination.ip(),
                        UdpLowerLayer::SCTP_UDP_TUNNELING_PORT_OUTGOING,
                    );

                    let association = Association::connect(
                        self.resources.clone(),
                        self.ephemeral_port().unwrap(),
                        return_tx,
                        destination,
                        llp_destination,
                        None,
                        timeout,
                    );
                    self.associations.push(association);
                }
                Listen(port, return_tx) => {
                    let association = Association::listen(
                        self.resources.clone(),
                        port,
                        self.llp_listen_address,
                        self.stack_accept_tx.clone(),
                        return_tx,
                    );
                    self.associations.push(association);
                }
                Exit(return_tx) => {
                    // Immediate exit; no graceful closing of connections
                    return_tx.send(()).unwrap();
                    return Ok(Async::Ready(()));
                }
            }
        }

        // Poll association streams
        let mut closed = false; // If true, one or more associations closed.
        for association in self.associations.iter_mut() {
            match association.poll() {
                Ok(Async::Ready(Some(packet))) => {
                    self.outgoing_tx.start_send(packet).unwrap();
                    // TODO: handle start_send not-ready?
                    // TODO: get rid of outgoing_tx altogether?
                    // (do we still need it after changing association to a stream?)
                }
                Ok(Async::Ready(None)) => {
                    // End-of-stream: This association has closed, so remove it from our list.
                    assert_eq!(association.state, AssociationState::Closed);
                    closed = true;
                }
                Ok(Async::NotReady) => {} // Nothing to do.
                Err(_) => {
                    // TODO: handle error?
                }
            }
        }
        if closed {
            // Remove all closed associations.
            self.associations
                .retain(|a| a.state != AssociationState::Closed);
        }

        // Poll accept queue
        if let Ok(Async::Ready(Some(stack_accept_item))) = self.stack_accept_rx.poll() {
            let (association, mut callback) = stack_accept_item;
            self.associations.push(association);
            // TODO
            callback();
        }

        // Poll incoming packets
        //
        // This pattern of placing an item into intermediate storage (self.incoming_packet) is
        // similar to using the Forward combinator to connect a Stream to a Sink.  We do this
        // explicitly instead of using Forward, though, to avoid borrow-checker mess with our
        // Vec<Association>.
        if let Some(packet) = self.incoming_packet.take() {
            match self.send_to_association(packet)? {
                AsyncSink::Ready => {}
                AsyncSink::NotReady(p) => self.incoming_packet = Some(p),
            }
            // poll again
            futures::task::current().notify();
        }
        if self.incoming_packet.is_none() {
            match self.incoming_stream.poll() {
                Ok(Async::Ready(Some(packet))) => {
                    trace!("Incoming SCTP packet: {:?}", packet.sctp_packet);
                    self.incoming_packet = Some(packet);
                    // poll again
                    futures::task::current().notify();
                }
                Ok(Async::Ready(None)) => {}
                Ok(Async::NotReady) => {}
                Err(e) => {
                    panic!("lower-layer error: {:?}", e);
                }
            }
        }

        // Always return NotReady here, since this future will never complete.
        // (Except via the Exit command, above.)
        Ok(Async::NotReady)
    }
}
