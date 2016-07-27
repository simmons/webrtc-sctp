//! SCTP associations.  Most of the complexity of SCTP is here.

use futures::sync::mpsc;
use futures::sync::oneshot;
use futures::{self, Async, AsyncSink, Future, Poll, Sink, StartSend, Stream as FutureStream};
use rand;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::*;
use tokio_timer;

use error::{SctpError, SctpResult};
use packet::chunk::{
    AbortChunk, Chunk, CookieAckChunk, CookieEchoChunk, DataChunk, HeartbeatAckChunk,
    HeartbeatChunk, InitAckChunk, InitChunk, SackChunk, ShutdownAckChunk, ShutdownChunk,
    ShutdownCompleteChunk,
};
use packet::error_cause::ErrorCause;
use packet::parameter::Parameter;
use packet::{SctpHeader, SctpPacket, SSN, TSN};
use stack::association::retransmission::Retransmission;
use stack::cookie::Cookie;
use stack::queue::{OrderedDataQueue, OutgoingDataQueue, UnorderedDataQueue};
use stack::recvtracker::RecvTracker;
use stack::settings::DEFAULT_SCTP_PARAMETERS;
use stack::Packet;
use stack::StackResources;
use stack::Timeout;
use util::buffer::Buffer;
use Message;
use UserMessage;

mod retransmission;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AssociationState {
    Listen,
    Closed,
    CookieWait,
    CookieEchoed,
    Established,
    ShutdownPending,
    ShutdownSent,
    ShutdownReceived,
    ShutdownAckSent,
}

pub struct NetworkState {
    pub local_port: u16,
    pub sctp_peer: SocketAddr,
    llp_peer: SocketAddr,
    num_outbound_streams: u16,
    num_inbound_streams: u16,
}

struct ListenState {
    stack_accept_tx: mpsc::Sender<StackAcceptItem>,
    ulp_accept_tx: mpsc::Sender<mpsc::Sender<AssociationCommand>>,
}

struct ConnectState {
    return_tx: oneshot::Sender<SctpResult<mpsc::Sender<AssociationCommand>>>,
    cookie: Option<Vec<u8>>,
    timer: Option<tokio_timer::Sleep>,
}

struct DataState {
    send_queue: OutgoingDataQueue,
    sent_queue: OutgoingDataQueue,
    recv_queue: VecDeque<Message>,
    recv_tx: Option<oneshot::Sender<SctpResult<Option<UserMessage>>>>,
    recv_tracker: RecvTracker,
    next_send_tsn: TSN,
    streams: HashMap<u16, Stream>,
    unordered_queue: UnorderedDataQueue,
    // A send that is pending on queue availability
    deferred_send: Option<(Message, oneshot::Sender<SctpResult<()>>)>,
}

impl DataState {
    fn new(next_recv_tsn: TSN, next_send_tsn: TSN) -> DataState {
        DataState {
            send_queue: OutgoingDataQueue::new(),
            sent_queue: OutgoingDataQueue::new(),
            recv_queue: VecDeque::new(),
            recv_tx: None,
            recv_tracker: RecvTracker::new(next_recv_tsn, DEFAULT_ADVERTISED_RECEIVER_WINDOW),
            next_send_tsn: next_send_tsn,
            streams: HashMap::new(),
            unordered_queue: UnorderedDataQueue::new(),
            deferred_send: None,
        }
    }
    fn stream(&mut self, stream_id: u16) -> &mut Stream {
        use std::collections::hash_map::Entry::{Occupied, Vacant};
        let stream = match self.streams.entry(stream_id) {
            Vacant(entry) => entry.insert(Stream::new(stream_id)),
            Occupied(entry) => entry.into_mut(),
        };
        stream
    }

    /// Is all the send data flushed (send_queue empty) and acked (sent_queue empty)?
    fn is_outgoing_empty(&self) -> bool {
        self.send_queue.is_empty() && self.sent_queue.is_empty()
    }
}

/// The state associated with a single SCTP association.
pub struct Association {
    // Top-level state
    pub state: AssociationState,
    // Global-ish resources obtained from the stack
    resources: StackResources,
    // State related to the network identity and stream bounds
    pub network: NetworkState,
    // State related to data processing
    data: DataState,
    // State related to listening
    listen: Option<ListenState>,
    // State related to connecting
    connect: Option<ConnectState>,

    // Internal/API/etc.
    outgoing_packets: VecDeque<Packet>,
    command_tx: mpsc::Sender<AssociationCommand>,
    command_rx: mpsc::Receiver<AssociationCommand>,
    t1: Option<tokio_timer::Sleep>,
    t2: Option<tokio_timer::Sleep>,
    t5: Option<tokio_timer::Sleep>,
    recv_timeout: Option<Duration>,
    send_timeout: Option<Duration>,
    recv_timer: Option<tokio_timer::Sleep>,
    send_timer: Option<tokio_timer::Sleep>,

    //
    // SCTP packet header fields
    //

    // Our verification tag which we provide to the remote endpoint as
    // the initiate tag field of INIT or INIT ACK.  We will verify that
    // all packets received from the remote endpoint have this tag.
    local_verification_tag: u32,
    // The remote endpoint's verification tag which is provided to us as
    // the initiate tag field of INIT or INIT ACK.  We will include this
    // verification tag in all outgoing packets.
    peer_verification_tag: u32,

    // Other fields (TODO: consider moving to other structs)

    // The highest cumulative TSN ack received.
    cumulative_tsn_ack_point: TSN,
    // The current calculated peer receiver window.
    peer_rwnd: u32,

    // If the outer option is Some, then a close is scheduled.  (For example, we've sent an abort packet, and
    // are waiting for it to clear the queue before reaping the association.)  The inner option may
    // contain a oneshot sender used to notify an interested party that the abort has completed.
    do_close: Option<Option<oneshot::Sender<()>>>,

    // Retransmission Timeouts (RTO)
    // The retransmission module performs periodic measurements of round-trip time, maintains an
    // ongoing "smoothed" round-trip time with variance, and adjusts the retransmission timeout
    // accordingly.
    rtx: retransmission::State,
}

impl fmt::Debug for Association {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Association({}->{}, {:?})",
            self.network.local_port, self.network.sctp_peer, self.state
        )
    }
}

pub struct Stream {
    #[allow(unused)]
    id: u16,
    next_ssn: SSN,
    ordered_queue: OrderedDataQueue,
}

impl Stream {
    pub fn new(id: u16) -> Stream {
        Stream {
            id,
            next_ssn: SSN::new(0),
            ordered_queue: OrderedDataQueue::new(),
        }
    }
}

const DEFAULT_ADVERTISED_RECEIVER_WINDOW: u32 = 128 * 1024;
const DEFAULT_OUTBOUND_STREAMS: u16 = 10;
const DEFAULT_INBOUND_STREAMS: u16 = 2048;
pub const DEFAULT_ACCEPT_QUEUE_SIZE: usize = 8;

const DEFAULT_CONNECT_TIMEOUT: Option<Duration> = None;
const DEFAULT_RECV_TIMEOUT: Option<Duration> = None;
const DEFAULT_SEND_TIMEOUT: Option<Duration> = None;

pub type StackAcceptItem = (Association, Box<FnMut() -> ()>);
pub type AssociationCommandSender = mpsc::Sender<AssociationCommand>;
pub type AcceptQueueReceiver = mpsc::Receiver<AssociationCommandSender>;

#[derive(Debug)]
pub enum AssociationCommand {
    Send(UserMessage, oneshot::Sender<SctpResult<()>>),
    Recv(oneshot::Sender<SctpResult<Option<UserMessage>>>),
    Shutdown(oneshot::Sender<SctpResult<()>>),
    Abort(oneshot::Sender<()>),
    SetSendTimeout(Timeout, oneshot::Sender<()>),
    SetRecvTimeout(Timeout, oneshot::Sender<()>),
}

impl Association {
    #[inline]
    #[allow(unused)]
    fn timer(&self, duration: Duration) -> Option<tokio_timer::Sleep> {
        Some(self.resources.timer.sleep(duration))
    }

    #[inline]
    fn timer_opt(&self, duration: Option<Duration>) -> Option<tokio_timer::Sleep> {
        match duration {
            Some(duration) => Some(self.resources.timer.sleep(duration)),
            None => None,
        }
    }

    #[inline]
    fn timer_ms(&self, milliseconds: u64) -> Option<tokio_timer::Sleep> {
        Some(
            self.resources
                .timer
                .sleep(Duration::from_millis(milliseconds)),
        )
    }

    fn state(&mut self, new_state: AssociationState) {
        let old_state = self.state;
        self.state = new_state;
        info!("State transition: {:?} -> {:?}", old_state, new_state);
    }

    fn instantiate(
        state: AssociationState,
        resources: StackResources,
        network_state: NetworkState,
        initial_recv_tsn: TSN,
        next_send_tsn: TSN,
        listen_state: Option<ListenState>,
        connect_state: Option<ConnectState>,
        local_verification_tag: u32,
        peer_verification_tag: u32,
        peer_rwnd: u32,
    ) -> Association {
        let (command_tx, command_rx) = mpsc::channel::<AssociationCommand>(0);
        let outgoing_packets = match state {
            AssociationState::Listen => VecDeque::with_capacity(0),
            _ => VecDeque::new(),
        };
        Association {
            state,
            resources,
            network: network_state,
            data: DataState::new(initial_recv_tsn, next_send_tsn),
            listen: listen_state,
            connect: connect_state,
            outgoing_packets,
            command_tx,
            command_rx,
            t1: None,
            t2: None,
            t5: None,
            recv_timeout: DEFAULT_RECV_TIMEOUT,
            send_timeout: DEFAULT_SEND_TIMEOUT,
            recv_timer: None,
            send_timer: None,
            local_verification_tag,
            peer_verification_tag,
            cumulative_tsn_ack_point: next_send_tsn - 1,
            peer_rwnd,
            do_close: None,
            rtx: retransmission::State::new(next_send_tsn - 1),
        }
    }

    fn instantiate_listen(
        local_port: u16,
        llp_local: SocketAddr,
        ulp_accept_tx: mpsc::Sender<mpsc::Sender<AssociationCommand>>,
        resources: StackResources,
        stack_accept_tx: mpsc::Sender<StackAcceptItem>,
    ) -> Association {
        // The convention (in UDP/TCP at least) is to represent listening sockets
        // with a zeroed peer address/port (e.g. INADDR_ANY or in6addr_any).
        fn inaddr_any() -> IpAddr {
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        }
        fn in6addr_any() -> IpAddr {
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
        }
        let peer = match llp_local.ip() {
            IpAddr::V4(_) => SocketAddr::new(inaddr_any(), 0),
            IpAddr::V6(_) => SocketAddr::new(in6addr_any(), 0),
        };

        Self::instantiate(
            AssociationState::Listen,
            resources,
            NetworkState {
                local_port,
                sctp_peer: peer,
                llp_peer: peer,
                // TODO: Allow the application layer to set these
                num_outbound_streams: DEFAULT_OUTBOUND_STREAMS,
                num_inbound_streams: DEFAULT_INBOUND_STREAMS,
            },
            TSN::new(0),
            TSN::new(0),
            Some(ListenState {
                stack_accept_tx,
                ulp_accept_tx,
            }),
            None, // connect state
            0,    // local verification tag
            0,    // peer verification tag
            0,    // peer receiver window
        )
    }

    fn instantiate_accept(
        listen_association: &Association,
        cookie: &Cookie,
        sctp_peer: SocketAddr,
        llp_peer: SocketAddr,
        num_outbound_streams: u16,
        num_inbound_streams: u16,
    ) -> Association {
        Self::instantiate(
            AssociationState::Established,
            listen_association.resources.clone(),
            NetworkState {
                local_port: listen_association.network.local_port,
                sctp_peer,
                llp_peer,
                num_outbound_streams,
                num_inbound_streams,
            },
            cookie.initial_recv_tsn,
            cookie.initial_send_tsn,
            None, // listen state
            None, // connect state
            cookie.local_verification_tag,
            cookie.peer_verification_tag,
            cookie.peer_rwnd,
        )
    }

    fn instantiate_connect(
        local_port: u16,
        sctp_peer: SocketAddr,
        llp_peer: SocketAddr,
        return_tx: oneshot::Sender<SctpResult<mpsc::Sender<AssociationCommand>>>,
        resources: StackResources,
        num_outbound_streams: u16,
        num_inbound_streams: u16,
        local_verification_tag: u32,
        next_send_tsn: TSN,
        timeout: Timeout,
    ) -> Association {
        let timer = timeout.timer(&resources.timer, DEFAULT_CONNECT_TIMEOUT);
        Self::instantiate(
            AssociationState::CookieWait,
            resources,
            NetworkState {
                local_port,
                sctp_peer,
                llp_peer,
                num_outbound_streams,
                num_inbound_streams,
            },
            TSN::new(0), // recreate with real recv_tsn on INIT-ACK
            next_send_tsn,
            None, // listen state
            Some(ConnectState {
                return_tx,
                cookie: None,
                timer,
            }),
            local_verification_tag,
            // Use peer tag of 0 for sending INIT, then replace with the value received from the
            // peer.
            0,
            0, // peer receiver window -- will be populated on INIT ACK.
        )
    }

    pub fn listen(
        resources: StackResources,
        local_port: u16,
        llp_local: SocketAddr,
        stack_accept_tx: mpsc::Sender<StackAcceptItem>,
        return_tx: oneshot::Sender<(AssociationCommandSender, AcceptQueueReceiver)>,
    ) -> Association {
        let (ulp_accept_tx, ulp_accept_rx) =
            mpsc::channel::<AssociationCommandSender>(DEFAULT_ACCEPT_QUEUE_SIZE);

        let association = Self::instantiate_listen(
            local_port,
            llp_local,
            ulp_accept_tx,
            resources,
            stack_accept_tx,
        );

        // This is silly to use a oneshot to return instead of just returning it from this
        // function, but we do this for consistency with the other functions (e.g. connect())
        // where a oneshot is required because multiple steps must happen.
        return_tx
            .send((association.command_tx.clone(), ulp_accept_rx))
            .unwrap();

        association
    }

    fn handle_init(&mut self, init: &InitChunk, sctp_peer: SocketAddr, llp_peer: SocketAddr) {
        let initiate_tag = random_tag();
        let initial_send_tsn = TSN::new(initiate_tag);
        let cookie = Cookie::new(
            self.network.local_port,
            sctp_peer,
            llp_peer,
            initiate_tag,
            init.initiate_tag,
            initial_send_tsn,
            TSN::new(init.initial_tsn),
            init.a_rwnd,
            init.num_outbound_streams,
            init.num_inbound_streams,
        );
        let cookie_parameter =
            Parameter::StateCookie(cookie.serialize(&self.resources.secret).unwrap());

        let init_ack_chunk = Chunk::InitAck(InitAckChunk {
            initiate_tag: initiate_tag,
            a_rwnd: DEFAULT_ADVERTISED_RECEIVER_WINDOW,
            num_outbound_streams: self.network.num_outbound_streams,
            num_inbound_streams: self.network.num_inbound_streams,
            // "Initial TSN (I-TSN): 32 bits (unsigned integer).
            // Defines the initial TSN that the sender will use.  The valid range
            // is from 0 to 4294967295.  This field MAY be set to the value of
            // the Initiate Tag field."
            initial_tsn: initial_send_tsn.0,
            parameters: vec![cookie_parameter],
        });

        // TODO
        self.send_chunk_explicit(init_ack_chunk, sctp_peer, llp_peer, init.initiate_tag);
        // "Note: After sending out INIT ACK with the State Cookie parameter,
        // "Z" MUST NOT allocate any resources or keep any states for the new
        // association.  Otherwise, "Z" will be vulnerable to resource
        // attacks."
        // So, no timers, no retransmits of INIT ACK.
    }

    fn handle_cookie_echo(
        &mut self,
        cookie_echo: &CookieEchoChunk,
        sctp_peer: SocketAddr,
        llp_peer: SocketAddr,
        verification_tag: u32,
    ) {
        // Confirm that the stack accept queue can accept a new association.
        match self.listen {
            Some(ref mut listen) => match listen.stack_accept_tx.poll_ready() {
                Ok(Async::Ready(_)) => {}
                Ok(Async::NotReady) => {
                    warn!("Stack accept queue full: dropping incoming COOKIE ECHO.");
                    return;
                }
                Err(_) => {
                    warn!("Stack accept queue error: dropping incoming COOKIE ECHO.");
                    return;
                }
            },
            None => unreachable!(),
        };

        // Confirm that the ULP accept queue can accept a new association.
        match self.listen {
            Some(ref mut listen) => match listen.ulp_accept_tx.poll_ready() {
                Ok(Async::Ready(_)) => {}
                Ok(Async::NotReady) => {
                    warn!("ULP accept queue full: dropping incoming COOKIE ECHO.");
                    return;
                }
                Err(_) => {
                    warn!("ULP accept queue error: dropping incoming COOKIE ECHO.");
                    return;
                }
            },
            None => unreachable!(),
        };

        // Deserialize the cookie, and verify its MAC.
        let cookie = match Cookie::deserialize(&self.resources.secret, &cookie_echo.cookie) {
            Ok(c) => c,
            Err(e) => {
                warn!("bad cookie: {}", e);
                return;
            }
        };

        // Verify that the cookie parameters match the incoming packet.
        if verification_tag != cookie.local_verification_tag {
            warn!(
                "Bad verification tag in COOKIE ECHO: {} != {}",
                verification_tag, cookie.local_verification_tag
            );
            return;
        }
        if self.network.local_port != cookie.local_port {
            warn!("invalid local port in cookie");
            return;
        }
        if sctp_peer != cookie.sctp_peer {
            warn!(
                "invalid SCTP peer cookie: {} != {}",
                sctp_peer, cookie.sctp_peer
            );
            return;
        }
        if llp_peer != cookie.llp_peer {
            warn!(
                "invalid LLP peer in cookie: {} != {}",
                llp_peer, cookie.llp_peer
            );
            return;
        }

        // Send COOKIE ACK
        let cookie_ack_chunk = Chunk::CookieAck(CookieAckChunk {});
        self.send_chunk_explicit(
            cookie_ack_chunk,
            sctp_peer,
            llp_peer,
            cookie.peer_verification_tag,
        );

        // Create new association
        let association = Self::instantiate_accept(
            &self,
            &cookie,
            sctp_peer,
            llp_peer,
            u16::min(
                cookie.peer_num_outbound_streams,
                self.network.num_inbound_streams,
            ),
            u16::min(
                cookie.peer_num_inbound_streams,
                self.network.num_outbound_streams,
            ),
        );
        trace!("ACCEPT({:?}): {:?}", association.state, sctp_peer);

        // Supply association to stack
        let mut ulp_accept_tx_clone = match self.listen {
            Some(ref listen) => listen.ulp_accept_tx.clone(),
            None => unreachable!(),
        };

        let command_tx_clone = association.command_tx.clone();
        match self.listen {
            Some(ref mut listen) => {
                listen
                    .stack_accept_tx
                    .try_send((
                        association,
                        Box::new(move || {
                            // Supply association command queue to the ULP accept queue.
                            ulp_accept_tx_clone
                                .try_send(command_tx_clone.clone())
                                .unwrap();
                        }),
                    )).unwrap()
            }
            None => unreachable!(),
        };
    }

    pub fn connect(
        resources: StackResources,
        local_port: u16,
        return_tx: oneshot::Sender<SctpResult<mpsc::Sender<AssociationCommand>>>,
        destination: SocketAddr,
        llp_destination: SocketAddr,
        outbound_stream_count: Option<u16>,
        timeout: Timeout,
    ) -> Association {
        let initiate_tag = random_tag();
        let initial_send_tsn = initiate_tag;
        let num_inbound_streams = DEFAULT_INBOUND_STREAMS;
        let num_outbound_streams = outbound_stream_count.unwrap_or(DEFAULT_OUTBOUND_STREAMS);

        let mut association = Self::instantiate_connect(
            local_port,
            destination,
            llp_destination,
            return_tx,
            resources,
            num_outbound_streams,
            num_inbound_streams,
            initiate_tag, // local verification tag
            TSN::new(initial_send_tsn),
            timeout,
        );
        association.send_init();
        association
    }

    fn send_init(&mut self) {
        let init_chunk = Chunk::Init(InitChunk {
            initiate_tag: self.local_verification_tag,
            a_rwnd: DEFAULT_ADVERTISED_RECEIVER_WINDOW,
            num_outbound_streams: self.network.num_outbound_streams,
            num_inbound_streams: self.network.num_inbound_streams,
            // "Initial TSN (I-TSN): 32 bits (unsigned integer).
            // Defines the initial TSN that the sender will use.  The valid range
            // is from 0 to 4294967295.  This field MAY be set to the value of
            // the Initiate Tag field."
            initial_tsn: self.data.next_send_tsn.0,
            parameters: vec![],
        });
        self.send_chunk(init_chunk);

        // Start (or restart) T1-init timer
        // TODO: Use actual RTO algorithm
        self.t1 = self.timer_ms(DEFAULT_SCTP_PARAMETERS.rto_initial);
    }

    fn handle_init_ack(&mut self, init_ack: &InitAckChunk) {
        // Stop T1-init timer
        self.t1 = None;

        self.peer_verification_tag = init_ack.initiate_tag;
        self.data.recv_tracker = RecvTracker::new(
            TSN::new(init_ack.initial_tsn),
            DEFAULT_ADVERTISED_RECEIVER_WINDOW,
        );
        self.peer_rwnd = init_ack.a_rwnd;

        // Calculate the actual number of streams for this association.
        self.network.num_inbound_streams = u16::min(
            init_ack.num_outbound_streams,
            self.network.num_inbound_streams,
        );
        self.network.num_outbound_streams = u16::min(
            init_ack.num_inbound_streams,
            self.network.num_outbound_streams,
        );

        // Extract the cookie
        let cookie = &init_ack
            .parameters
            .iter()
            .filter_map(|x| match x {
                &Parameter::StateCookie(ref c) => Some(c),
                _ => None,
            }).next();
        let cookie = match *cookie {
            Some(c) => c,
            None => {
                error!("No StateCookie parameter in INIT ACK.");
                return;
            }
        };
        match self.connect {
            Some(ref mut connect) => connect.cookie = Some(cookie.clone()),
            None => unreachable!(),
        }
        self.send_cookie_echo();
        self.state(AssociationState::CookieEchoed);
    }

    fn send_cookie_echo(&mut self) {
        let cookie = match self.connect {
            Some(ref mut connect) => match connect.cookie {
                Some(ref cookie) => cookie.clone(),
                None => unreachable!(),
            },
            None => unreachable!(),
        };
        let cookie_echo = Chunk::CookieEcho(CookieEchoChunk { cookie });
        self.send_chunk(cookie_echo);

        // Start (or restart) T1-cookie timer
        // TODO: Use actual RTO algorithm
        self.t1 = self.timer_ms(DEFAULT_SCTP_PARAMETERS.rto_initial);
    }

    fn handle_cookie_ack(&mut self, _: &CookieAckChunk) {
        // Stop T1-cookie timer
        self.t1 = None;

        self.state(AssociationState::Established);

        match self.connect.take() {
            Some(connect) => {
                connect.return_tx.send(Ok(self.command_tx.clone())).unwrap();
            }
            None => unreachable!(),
        };
        self.connect = None;
    }

    fn send_chunk(&mut self, chunk: Chunk) {
        // TODO: This could be optimized by taking a reference to a chunk, and using
        // an alternate packet serializer that can use chunk references.
        // Or, just change outgoing_packets to outgoing_chunks, since the header and llp_address
        // will always be the same?

        trace!("SEND({:?}): {:?}", self.state, chunk);
        let packet = Packet {
            sctp_packet: SctpPacket {
                header: SctpHeader {
                    source_port: self.network.local_port,
                    destination_port: self.network.sctp_peer.port(),
                    verification_tag: self.peer_verification_tag,
                },
                chunks: vec![chunk],
            },
            llp_address: self.network.llp_peer,
        };
        self.outgoing_packets.push_back(packet);
    }

    fn send_chunk_explicit(
        &mut self,
        chunk: Chunk,
        sctp_peer: SocketAddr,
        llp_peer: SocketAddr,
        peer_verification_tag: u32,
    ) {
        trace!("SEND({:?}): {:?}", self.state, chunk);
        let packet = Packet {
            sctp_packet: SctpPacket {
                header: SctpHeader {
                    source_port: self.network.local_port,
                    destination_port: sctp_peer.port(),
                    verification_tag: peer_verification_tag,
                },
                chunks: vec![chunk],
            },
            llp_address: llp_peer,
        };
        self.outgoing_packets.push_back(packet);
    }

    fn handle_incoming(&mut self, packet: Packet) {
        let mut sctp_packet = packet.sctp_packet;
        let sctp_peer = SocketAddr::new(packet.llp_address.ip(), sctp_packet.header.source_port);

        // Early chunk analysis
        let mut has_init = false;
        let mut has_cookie_echo = false;
        let mut _has_shutdown_complete = false;
        let mut _has_abort = false;
        for chunk in &mut sctp_packet.chunks {
            match chunk {
                &mut Chunk::Init(_) => has_init = true,
                &mut Chunk::CookieEcho(_) => has_cookie_echo = true,
                &mut Chunk::ShutdownComplete(_) => _has_shutdown_complete = true,
                &mut Chunk::Abort(_) => _has_abort = true,
                _ => {}
            }
        }

        // Verifications
        if has_init {
            // "An INIT chunk MUST be the only chunk in the SCTP packet carrying it."
            if sctp_packet.chunks.len() > 1 {
                error!("init chunk in packet with multiple chunks");
                return;
            }
            // "A packet containing an INIT chunk MUST have a zero Verification Tag."
            if sctp_packet.header.verification_tag != 0 {
                error!("invalid verification tag for init packet");
                return;
            }
        } else if has_cookie_echo {
            // No verification check here -- the COOKIE ECHO handler must unpack
            // the state cookie before verification.
        } else {
            if sctp_packet.header.verification_tag != self.local_verification_tag {
                error!("error: invalid verification tag for this association");
                return;
            }
        }
        // "A packet containing a SHUTDOWN COMPLETE chunk with the T bit
        // set MUST have the Verification Tag copied from the packet with
        // the SHUTDOWN ACK chunk."
        // TODO
        // "A packet containing an ABORT chunk may have the verification
        // tag copied from the packet that caused the ABORT to be sent.
        // For details see Section 8.4 and Section 8.5.
        // TODO

        // Dispatch chunks
        for mut chunk in sctp_packet.chunks.iter_mut() {
            self.handle_chunk(
                &mut chunk,
                sctp_peer,
                packet.llp_address,
                sctp_packet.header.verification_tag,
            );
        }
    }

    fn handle_chunk(
        &mut self,
        chunk: &mut Chunk,
        sctp_peer: SocketAddr,
        llp_peer: SocketAddr,
        verification_tag: u32,
    ) {
        trace!("RECV({:?}): {:?}", self.state, chunk);

        // Dispatch
        use self::AssociationState::*;
        use packet::chunk::Chunk::*;
        match (chunk, &self.state) {
            (&mut InitAck(ref init_ack), &CookieWait) => {
                self.handle_init_ack(init_ack);
            }
            (&mut CookieAck(ref cookie_ack), &CookieEchoed) => {
                self.handle_cookie_ack(cookie_ack);
            }
            (&mut Init(ref init), &Listen) => {
                self.handle_init(init, sctp_peer, llp_peer);
            }
            (&mut CookieEcho(ref cookie_echo), &Listen) => {
                self.handle_cookie_echo(cookie_echo, sctp_peer, llp_peer, verification_tag);
            }
            (&mut Data(ref mut data), &Established)
            | (&mut Data(ref mut data), &ShutdownPending)
            | (&mut Data(ref mut data), &ShutdownSent) => {
                self.handle_data(data).unwrap();
            }
            // HEARTBEATs are sent between the sender's ESTABLISHED and send of
            // SHUTDOWN/SHUTDOWN-ACK.
            // HEARTBEATs are echoed after COOKIE-ECHOED/ESTABLISHED until
            // SHUTDOWN-SENT/SHUTDOWN-ACK-SENT.
            (&mut Heartbeat(ref heartbeat), &CookieEchoed)
            | (&mut Heartbeat(ref heartbeat), &Established)
            | (&mut Heartbeat(ref heartbeat), &ShutdownPending)
            | (&mut Heartbeat(ref heartbeat), &ShutdownReceived) => {
                self.handle_heartbeat(heartbeat);
            }

            // "A SACK MUST be processed in ESTABLISHED, SHUTDOWN-PENDING, and
            // SHUTDOWN-RECEIVED.  An incoming SACK MAY be processed in COOKIE-
            // ECHOED.  A SACK in the CLOSED state is out of the blue and SHOULD be
            // processed according to the rules in Section 8.4.  A SACK chunk
            // received in any other state SHOULD be discarded."
            (&mut Sack(ref sack), &CookieEchoed)
            | (&mut Sack(ref sack), &Established)
            | (&mut Sack(ref sack), &ShutdownPending)
            | (&mut Sack(ref sack), &ShutdownReceived) => {
                self.handle_sack(sack);
            }

            (&mut Shutdown(ref shutdown), &Established)
            | (&mut Shutdown(ref shutdown), &ShutdownSent) => {
                self.handle_shutdown(shutdown);
            }

            (&mut ShutdownAck(ref shutdown_ack), &ShutdownSent)
            | (&mut ShutdownAck(ref shutdown_ack), &ShutdownAckSent) => {
                self.handle_shutdown_ack(shutdown_ack);
            }

            (&mut ShutdownComplete(ref shutdown_complete), &ShutdownAckSent) => {
                self.handle_shutdown_complete(shutdown_complete);
            }

            (c, _) => {
                // TODO: ABORT?
                warn!("UNEXPECTED({:?}): {:?}", self.state, c);
            }
        }
    }

    fn handle_data(&mut self, data: &mut DataChunk) -> SctpResult<()> {
        // DATA chunks MUST only be received according to the rules below in
        // ESTABLISHED, SHUTDOWN-PENDING, and SHUTDOWN-SENT.  A DATA chunk
        // received in CLOSED is out of the blue and SHOULD be handled per
        // Section 8.4.  A DATA chunk received in any other state SHOULD be
        // discarded.
        use self::AssociationState::*;
        match self.state {
            Established | ShutdownPending | ShutdownSent => {}
            _ => return Err(SctpError::BadState),
        }

        // Do we have space in the receiver window for this chunk?
        if self.data.recv_tracker.rwnd() == 0 {
            // drop this DATA chunk
            return Ok(());
        }

        // Add buffer tracking to data chunks here, so its bytes are accounted in the rwnd.
        data.buffer.track(self.data.recv_tracker.buffer_tracker());

        // 1. TSN tracking, SACKs, etc.

        if !self.data.recv_tracker.track(&data) {
            // Duplicate chunk -- send SACK immediately
            let sack = Chunk::Sack(self.data.recv_tracker.sack());
            self.send_chunk(sack);
            return Ok(());
        }

        // TODO: This a quick hack to keep the peer from retransmitting.
        // We actually only want to send SACKS at certain times.
        let sack = Chunk::Sack(self.data.recv_tracker.sack());
        self.send_chunk(sack);

        // 2. Reordering and message reassembly

        // TODO: This could be optimized by only cloning for data chunks that precede
        // other chunks in a packet (in handle_incoming()).
        let data: DataChunk = data.clone();
        let messages: Vec<Message> = if data.unordered {
            // TODO: ABORT on error
            self.data
                .unordered_queue
                .enqueue(data)?
                .into_iter()
                .collect()
        } else {
            // 2. Demux (ordered)
            let mut stream = self.data.stream(data.stream_id);
            // TODO: ABORT on error
            stream.ordered_queue.enqueue(data)?
        };

        // 3. Provide messages to the upper layer.

        // If the application is actively blocked on recv(), provide the data right away.
        // Otherwise, push it into the recv buffer.
        for message in messages {
            match self.data.recv_tx.take() {
                Some(tx) => {
                    tx.send(Ok(Some(UserMessage::from_message(message))))
                        .unwrap();
                    self.recv_timer = None;
                }
                None => {
                    self.data.recv_queue.push_back(message);
                    futures::task::current().notify();
                }
            };
        }

        Ok(())
    }

    fn handle_heartbeat(&mut self, heartbeat: &HeartbeatChunk) {
        let info = match heartbeat.parameter {
            Parameter::HeartbeatInfo(ref info) => info,
            _ => {
                // TODO: handle ERROR
                unreachable!()
            }
        };
        self.send_chunk(Chunk::HeartbeatAck(HeartbeatAckChunk {
            parameter: Parameter::HeartbeatInfo(info.to_owned()),
        }));
    }

    fn handle_sack(&mut self, sack: &SackChunk) {
        if sack.cumulative_tsn_ack < self.cumulative_tsn_ack_point {
            // Drop SACK if its cumulative TSN is below the high water mark.
            // This means it's an old SACK that was received out-of-order.
            return;
        }
        self.process_new_cumulative_tsn_ack(sack.cumulative_tsn_ack);
        self.process_new_receiver_window(sack.a_rwnd);
        Retransmission::on_gap_ack_blocks(self, sack.cumulative_tsn_ack, &sack.gap_ack_blocks);

        // TODO: Some "Fast Recovery" thing

        // Using the updated rwnd, try to send any pending chunks (if possible)
        self.flush_send();

        self.process_post_ack();
    }

    fn process_new_cumulative_tsn_ack(&mut self, cumulative_tsn_ack: TSN) {
        self.cumulative_tsn_ack_point = cumulative_tsn_ack;
        let earliest_outstanding_tsn = self.data.sent_queue.front().map(|c| c.tsn);
        // Release all sent_queue chunks that have been acknowledged by the cumulative TSN.
        loop {
            match self.data.sent_queue.front() {
                Some(chunk) if chunk.tsn <= cumulative_tsn_ack => {}
                _ => break,
            }
            self.data.sent_queue.pop();
        }
        // Allow the retransmit clock to perform measurements
        Retransmission::on_cumulative_ack(self, cumulative_tsn_ack, earliest_outstanding_tsn);
    }

    fn process_new_receiver_window(&mut self, a_rwnd: u32) {
        // Reset the peer receiver window to be as indicated by the SACK, minus
        // any chunks in flight.
        let bytes_in_flight = self.data.sent_queue.bytes();
        self.peer_rwnd = if (a_rwnd as usize) > bytes_in_flight {
            a_rwnd - (bytes_in_flight as u32)
        } else {
            0
        };
    }

    /// Certain post-ack processing must occur after an ack has been received and handled.
    fn process_post_ack(&mut self) {
        // If we are shutting down, if all the outgoing data is flushed and acked, we can proceed
        // to the next step.
        if self.data.is_outgoing_empty() {
            match self.state {
                AssociationState::ShutdownPending => {
                    self.shutdown_send();
                }
                AssociationState::ShutdownReceived => {
                    self.shutdown_ack_send();
                }
                _ => {}
            }
        }
    }

    fn data_mtu(&self) -> usize {
        // TODO: TEMPORARY HARD-CODED VALUES!  Perform Path MTU Discovery!

        const IPV4_MIN_MTU: usize = 576;
        const IPV4_MAX_HEADER_SIZE: usize = 60; // minimum/typical is 20
        const UDP_HEADER_SIZE: usize = 8;
        const SCTP_HEADER_SIZE: usize = 12;
        const DATA_CHUNK_HEADER_SIZE: usize = 16;
        const IDATA_CHUNK_HEADER_SIZE: usize = 20;

        // See the Path MTU notes in NOTES.txt

        // Calculate a "safe" maximum data size of 476.
        // This is ridiculous since the true size will usually be around 1440, but this is only
        // temporary until we can employ a strategy for Path MTU discovery.  (This will need to be
        // handled in conjunction with the LLP, information from the local network interface,
        // possible handling of the relevant ICMP messages, etc.)
        IPV4_MIN_MTU
            - IPV4_MAX_HEADER_SIZE
            - UDP_HEADER_SIZE
            - SCTP_HEADER_SIZE
            - usize::max(DATA_CHUNK_HEADER_SIZE, IDATA_CHUNK_HEADER_SIZE)
    }

    fn send_msg(&mut self, message: Message) -> SctpResult<()> {
        // 6.  User Data Transfer
        // Data transmission MUST only happen in the ESTABLISHED, SHUTDOWN-
        // PENDING, and SHUTDOWN-RECEIVED states.  The only exception to this is
        // that DATA chunks are allowed to be bundled with an outbound COOKIE
        // ECHO chunk when in the COOKIE-WAIT state.
        use self::AssociationState::*;
        match self.state {
            Established | ShutdownPending | ShutdownReceived => {}
            _ => return Err(SctpError::BadState),
        }

        // Validate stream ID is within bounds for this association
        // TODO

        // Assign an SSN
        let ssn = if message.unordered {
            SSN::new(0)
        } else {
            let ssn = self.data.stream(message.stream_id).next_ssn;
            self.data.stream(message.stream_id).next_ssn.incr();
            ssn
        };

        // Fragment the message into one or more DATA chunks
        let data_mtu = self.data_mtu();
        let data_size = message.buffer.len();
        let mut position = 0;
        while position < data_size {
            let fragment_size;
            let ending_fragment;
            if position + data_mtu >= data_size {
                fragment_size = data_size - position;
                ending_fragment = true;
            } else {
                fragment_size = data_mtu;
                ending_fragment = false;
            };
            let chunk = DataChunk {
                unordered: message.unordered,
                beginning_fragment: position == 0,
                ending_fragment,
                tsn: self.data.next_send_tsn,
                stream_id: message.stream_id,
                ssn,
                payload_protocol_id: message.payload_protocol_id,
                buffer: Buffer::new(&message.buffer[position..position + fragment_size]),
            };

            // Enqueue this chunk
            self.data.send_queue.push(chunk);
            self.data.next_send_tsn.incr();
            position += fragment_size;
        }

        // Try to flush the send queue
        self.flush_send();

        Ok(())
    }

    /// Before the application layer can submit a message to send_msg(), this function
    /// is called to make sure sufficient buffer space is available and backpressure is applied if
    /// not.  This results in message-level granularity, which isn't perfect, but should suffice
    /// for now.  For example, if the send queue limit (determined via congestion control and local
    /// resource availability) is 128K, and the queue already contains 127K worth of pending
    /// chunks, and the caller tries to send a 128K message, then the queue will end up holding
    /// 255K worth of buffers.
    fn can_send(&mut self) -> bool {
        let limit = usize::min(
            // TODO: Do we really care about the peer_rwnd when we're just wanting to enqueue a new
            // message into the local send buffer?
            self.peer_rwnd as usize,
            DEFAULT_SCTP_PARAMETERS.max_send_queue,
        );
        let queued_bytes = self.data.send_queue.bytes();
        queued_bytes < limit
    }

    /// Does the peer receiver window allow us to transmit the next packet in the send queue?
    fn can_transmit(&mut self) -> bool {
        match self.data.send_queue.front() {
            Some(chunk) => chunk.buffer.len() <= self.peer_rwnd as usize,
            None => false, // nothing to transmit.
        }
    }

    fn flush_send(&mut self) {
        // TODO: call flush_send() again every time we update self.peer_rwnd in handle_sack()

        // dequeue chunks and send
        if self.can_transmit() {
            while let Some(chunk) = self.data.send_queue.pop() {
                // Reduce the peer receiver window by this chunk's bytes.
                let bytes = chunk.buffer.len();
                if (self.peer_rwnd as usize) < bytes {
                    self.peer_rwnd = 0;
                } else {
                    self.peer_rwnd -= bytes as u32;
                }
                // TODO: When we mark a chunk for retransmit, we need to increase peer_rwnd, then
                // decrease it again when the retransmit actually happens.

                // Notify the retransmit clock for the purposes of RTT measurement.
                Retransmission::on_outgoing_data(self, chunk.tsn);

                // TODO: This clone could be avoided with better plumbing.  (See note in send_chunk().)
                self.send_chunk(Chunk::Data(chunk.clone()));

                // Add to the sent queue.  (It will be removed when we receive a SACK cumulative TSN
                // acknowledgement that it was received.)
                self.data.sent_queue.push(chunk);

                // Verify we can continue to send before dequeuing another chunk.
                if !self.can_transmit() {
                    break;
                }
            }
        }

        // If there is a deferred send waiting, see if we can now enqueue it.
        // This creates a circular reference in the call graph (send_msg()<->flush_send()), but
        // since we take() the deferred message, recursion should be bounded.
        if self.can_send() {
            if let Some((message, return_tx)) = self.data.deferred_send.take() {
                return_tx.send(self.send_msg(message)).unwrap();
            }
        }
    }

    /// When all outgoing data is flushed and acked, we can proceed with local-initiated shutdown
    /// by sending the shutdown chunk.
    fn shutdown_send(&mut self) {
        // All the outgoing chunks have been flushed and acked, so we can send the ShutdownChunk.
        let sack = self.data.recv_tracker.sack();
        let shutdown = Chunk::Shutdown(ShutdownChunk {
            cumulative_tsn_ack: sack.cumulative_tsn_ack,
        });
        self.send_chunk(shutdown);

        // We must also send a SACK if received TSN gaps exist, since they can't be represented in
        // the shutdown chunk.
        if !sack.gap_ack_blocks.is_empty() {
            self.send_chunk(Chunk::Sack(sack));
        }

        // Start (or restart) the T2-shutdown timer.  This function will be called again if it
        // expires, and the ShutdownChunk (and possible SackChunk) re-sent.
        // TODO: Use actual RTO algorithm
        // TODO: Use correct timing
        self.t2 = Some(
            self.resources
                .timer
                .sleep(Duration::from_millis(DEFAULT_SCTP_PARAMETERS.rto_initial)),
        );

        // Start T5-shutdown-guard timer.  If this timer expires, abort.
        self.t5 = Some(self.resources.timer.sleep(Duration::from_millis(
            // If the 'T5-shutdown-guard' timer is used, it SHOULD be set to
            // the recommended value of 5 times 'RTO.Max'.
            5 * DEFAULT_SCTP_PARAMETERS.rto_max,
        )));

        // Transition
        self.state(AssociationState::ShutdownSent);
    }

    /// When all outgoing data is flushed and acked, we can proceed with peer-initiated shutdown
    /// by sending the shutdown-ack chunk.
    fn shutdown_ack_send(&mut self) {
        // All the outgoing chunks have been flushed and acked, so we can send the ShutdownAckChunk.
        let shutdown_ack = Chunk::ShutdownAck(ShutdownAckChunk {});
        self.send_chunk(shutdown_ack);

        // Start (or restart) the T2-shutdown timer.  This function will be called again if it
        // expires, and the ShutdownAckChunk re-sent.
        // TODO: Use actual RTO algorithm
        // TODO: Use correct timing
        self.t2 = Some(
            self.resources
                .timer
                .sleep(Duration::from_millis(DEFAULT_SCTP_PARAMETERS.rto_initial)),
        );

        // Transition
        self.state(AssociationState::ShutdownAckSent);
    }

    fn handle_shutdown(&mut self, shutdown: &ShutdownChunk) {
        // Process the shutdown's cumulative TSN ack the same as if it were
        // provided in a SACK chunk.
        self.process_new_cumulative_tsn_ack(shutdown.cumulative_tsn_ack);

        match self.state {
            AssociationState::ShutdownSent => {
                // If we receive a SHUTDOWN while in SHUTDOWN-SENT state, this means that the
                // two endpoints issued SHUTDOWN simultaneously and the SHUTDOWN chunks passed each
                // other on the network.  According to RFC 4960:
                //     "If an endpoint is in the SHUTDOWN-SENT state and receives a SHUTDOWN
                //     chunk from its peer, the endpoint shall respond immediately with a
                //     SHUTDOWN ACK to its peer, and move into the SHUTDOWN-ACK-SENT state
                //     restarting its T2-shutdown timer."
                // (Note that there is no outgoing data to flush if we are
                // already in the ShutdownSent state.)
                self.shutdown_ack_send();
            }
            AssociationState::Established => {
                self.state(AssociationState::ShutdownReceived);

                // If all the outgoing data is flushed and acked, we can proceed to the next
                // step.  Otherwise, wait until the final ack arrives and
                // transition to ShutdownAckSent in handle_sack().
                if self.data.is_outgoing_empty() {
                    self.shutdown_ack_send();
                }
            }
            _ => unreachable!(),
        };
    }

    fn handle_shutdown_ack(&mut self, _: &ShutdownAckChunk) {
        // stop timers
        self.t2 = None; // T2-shutdown
        self.t5 = None; // T5-shutdown-guard

        // Send SHUTDOWN COMPLETE
        let shutdown_complete = Chunk::ShutdownComplete(ShutdownCompleteChunk {
            verification_tag_reflected: false,
        });
        self.send_chunk(shutdown_complete);

        // Close association
        self.state(AssociationState::Closed);
        self.do_close = Some(None);
    }

    fn handle_shutdown_complete(&mut self, _: &ShutdownCompleteChunk) {
        // stop timers
        self.t2 = None; // T2-shutdown
        self.t5 = None; // T5-shutdown-guard

        // Close association
        self.state(AssociationState::Closed);
        self.do_close = Some(None);
    }

    fn shutdown_abort(&mut self) {
        // The T5-shutdown-guard timer expired, so abort the association.

        // Send ABORT
        let abort = Chunk::Abort(AbortChunk {
            verification_tag_reflected: false,
            // None of the RFC 4960 error causes really make sense for this situation.
            error_causes: vec![],
        });
        self.send_chunk(abort);

        // Close immediately
        self.state(AssociationState::Closed);
        self.do_close = Some(None);
    }
}

impl Sink for Association {
    type SinkItem = Packet;
    type SinkError = io::Error;

    fn start_send(&mut self, packet: Packet) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.handle_incoming(packet);
        Ok(AsyncSink::Ready)
    }
    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl FutureStream for Association {
    type Item = Packet;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Packet>, io::Error> {
        // Handle timeouts
        // TODO: This timer stuff is just begging to be refactored.

        if let Some(mut timeout) = self.t1.take() {
            match timeout.poll() {
                Ok(Async::Ready(_)) => {
                    info!("T1-TIMEOUT");
                    // TODO: track retransmit counts and close association if max is exceeded.
                    use self::AssociationState::*;
                    match self.state {
                        CookieWait => self.send_init(),
                        CookieEchoed => self.send_cookie_echo(),
                        _ => {}
                    };
                }
                Ok(Async::NotReady) => self.t1 = Some(timeout),
                Err(_) => {}
            }
        }
        if let Some(mut timeout) = self.t2.take() {
            match timeout.poll() {
                Ok(Async::Ready(_)) => {
                    info!("T2-TIMEOUT");
                    // TODO: track retransmit counts and close association if max is exceeded.
                    use self::AssociationState::*;
                    match self.state {
                        ShutdownSent => self.shutdown_send(),
                        ShutdownAckSent => self.shutdown_ack_send(),
                        _ => {}
                    };
                }
                Ok(Async::NotReady) => self.t2 = Some(timeout),
                Err(_) => {}
            }
        }
        if let Some(mut timeout) = self.rtx.timer.take() {
            match timeout.poll() {
                Ok(Async::Ready(_)) => {
                    info!("T3-RTX-TIMEOUT");
                    match self.state {
                        // TODO: restrict state?
                        _ => Retransmission::on_timeout(self),
                    };
                }
                Ok(Async::NotReady) => self.rtx.timer = Some(timeout),
                Err(_) => {}
            }
        }
        if let Some(mut timeout) = self.t5.take() {
            match timeout.poll() {
                Ok(Async::Ready(_)) => {
                    info!("T5-TIMEOUT");
                    // TODO: track retransmit counts and close association if max is exceeded.
                    use self::AssociationState::*;
                    match self.state {
                        ShutdownSent => self.shutdown_abort(),
                        _ => {}
                    };
                }
                Ok(Async::NotReady) => self.t5 = Some(timeout),
                Err(_) => {}
            }
        }

        let connect_timeout = match self.connect {
            Some(ref mut connect) => {
                match connect.timer {
                    Some(ref mut timer) => {
                        match timer.poll() {
                            Ok(Async::Ready(_)) => true,
                            Ok(Async::NotReady) => false,
                            Err(e) => {
                                error!("Error polling connect timer: {}", e);
                                true // abort connect
                            }
                        }
                    }
                    None => false,
                }
            }
            None => false,
        };
        if connect_timeout {
            info!("CONNECT-TIMEOUT");
            let mut connect = self.connect.take().unwrap();
            connect.timer = None;

            // Return a timeout error
            connect.return_tx.send(Err(SctpError::Timeout)).unwrap();

            // Send abort?
            // (Need to examine state, and possibly send an abort with the verification tag
            // reflected.)
            // TODO

            // Close the association
            self.state(AssociationState::Closed);
            self.do_close = Some(None);
        }

        let recv_timeout = match self.recv_timer {
            Some(ref mut timer) => {
                match timer.poll() {
                    Ok(Async::Ready(_)) => true,
                    Ok(Async::NotReady) => false,
                    Err(e) => {
                        error!("Error polling recv timer: {}", e);
                        true // time out recv()
                    }
                }
            }
            None => false,
        };
        if recv_timeout {
            info!("RECV-TIMEOUT");
            self.recv_timer = None;

            // Return a timeout error
            match self.data.recv_tx.take() {
                Some(tx) => tx.send(Err(SctpError::Timeout)).unwrap(),
                None => unreachable!(),
            }
        }

        let send_timeout = match self.send_timer {
            Some(ref mut timer) => {
                match timer.poll() {
                    Ok(Async::Ready(_)) => true,
                    Ok(Async::NotReady) => false,
                    Err(e) => {
                        error!("Error polling send timer: {}", e);
                        true // time out send()
                    }
                }
            }
            None => false,
        };
        if send_timeout {
            info!("SEND-TIMEOUT");
            self.send_timer = None;

            // Return a timeout error
            match self.data.deferred_send.take() {
                Some((_, tx)) => tx.send(Err(SctpError::Timeout)).unwrap(),
                None => unreachable!(),
            }
        }

        // Poll incoming commands
        if let Ok(Async::Ready(Some(command))) = self.command_rx.poll() {
            use self::AssociationCommand::*;
            match command {
                Send(buffer, return_tx) => {
                    if self.state != AssociationState::Established {
                        // Sending user data is only allowed in ESTABLISHED state.
                        // In particular, no new user data is allowed to be sent while a
                        // shutdown is in progress.
                        // (Technically we could allow user data to be enqueued during
                        // initialization, but we choose not to for implementation simplicity.)
                        return_tx.send(Err(SctpError::BadState)).unwrap();
                    } else {
                        let message = buffer.to_message();
                        if self.can_send() {
                            return_tx.send(self.send_msg(message)).unwrap();
                        } else if self.data.deferred_send.is_none() {
                            // Defer this send.  To supply backpressure, we won't send to the
                            // return_tx oneshot until this send can be enqueued.  The caller
                            // is expected to wait until this oneshot is triggered before invoking
                            // another send.  (Or else be prepared to receive SendQueueFull.)
                            // When queue space becomes available, we will check for a deferred send
                            // and process it.
                            self.send_timer = self.timer_opt(self.send_timeout);
                            self.data.deferred_send = Some((message, return_tx));
                        } else {
                            // The queue is full and a previous deferred send is already waiting to be
                            // enqueued.  (The caller obviously did not wait for the return_tx oneshot
                            // before trying another send.)
                            return_tx.send(Err(SctpError::SendQueueFull)).unwrap();
                        }
                    }
                }
                Recv(return_tx) => {
                    if self.data.recv_tx.is_some() {
                        panic!("concurrent recv()");
                    } else {
                        match self.data.recv_queue.pop_front() {
                            Some(message) => return_tx
                                .send(Ok(Some(UserMessage::from_message(message))))
                                .unwrap(),
                            None => {
                                self.recv_timer = self.timer_opt(self.recv_timeout);
                                self.data.recv_tx = Some(return_tx);
                            }
                        }
                    }
                }
                Abort(return_tx) => {
                    // Ungracefully close the association immediately.

                    if let Some(_) = self.do_close {
                        // Disallow concurrent aborts.
                        // TODO: return an error via the tx
                        return_tx.send(()).unwrap();
                    } else if self.state == AssociationState::Listen {
                        // Listen associations can simply close.
                        self.state(AssociationState::Closed);
                        return_tx.send(()).unwrap();
                        return Ok(Async::Ready(None));
                    } else {
                        // Send ABORT
                        let abort = Chunk::Abort(AbortChunk {
                            verification_tag_reflected: false,
                            error_causes: vec![ErrorCause::UserInitiatedAbort(vec![])],
                        });
                        self.send_chunk(abort);

                        // Close immediately
                        self.state(AssociationState::Closed);
                        self.do_close = Some(Some(return_tx));
                    }
                }
                Shutdown(return_tx) => {
                    // Verify that we are in a valid state for shutdown.
                    if self.state != AssociationState::Established {
                        // User-initiated shutdown is only allowed in ESTABLISHED state.
                        return_tx.send(Err(SctpError::BadState)).unwrap();
                    } else {
                        // Gracefully close the association
                        self.state(AssociationState::ShutdownPending);

                        // We respond to the application as soon as we change state, instead of waiting
                        // for shutdown to complete.  This is because the application needs to be able
                        // to consume received data in order for shutdown to progress.
                        // (We could consider a shutdown mode where received data is silently
                        // discarded, if that's something that applications really want.)
                        return_tx.send(Ok(())).unwrap();

                        // If all the outgoing data is flushed and acked, we can proceed to the next
                        // step.
                        if self.data.is_outgoing_empty() {
                            self.shutdown_send();
                        }
                    }
                }
                SetRecvTimeout(timeout, return_tx) => {
                    self.recv_timeout = timeout.duration(DEFAULT_RECV_TIMEOUT);
                    return_tx.send(()).unwrap();
                }
                SetSendTimeout(timeout, return_tx) => {
                    self.send_timeout = timeout.duration(DEFAULT_SEND_TIMEOUT);
                    return_tx.send(()).unwrap();
                }
            };

            // If there are more commands in the queue (i.e. command_rx.poll() would return
            // Async::Ready), they may not be polled in a timely fashion if we do not arrange
            // another poll via notify().  We do this instead of polling command_rx in a loop
            // to give fair scheduling to other steps (e.g. sending outgoing packets, etc.).
            futures::task::current().notify();
        }

        // Supply outgoing packets
        match self.outgoing_packets.pop_front() {
            Some(packet) => return Ok(Async::Ready(Some(packet))),
            None => {}
        }

        // If an abort was requested, wait until the ABORT has been sent,
        // then return and close the stream.
        // TODO: support non-user-initiated aborts that have no return_tx
        if self.outgoing_packets.is_empty() {
            if let Some(mut abort_return_tx) = self.do_close.take() {
                if let Some(abort_return_tx) = abort_return_tx.take() {
                    abort_return_tx.send(()).unwrap();
                }
                return Ok(Async::Ready(None));
            }
        }

        Ok(Async::NotReady)
    }
}

impl Drop for Association {
    fn drop(&mut self) {
        //info!("DROP association: {:?}", self);
    }
}

/// Generate a 32-bit random number suitable for use as an initiate tag.  This tag will be in the
/// range 1..(2^32-1) inclusive -- zero is not an allowable tag.
fn random_tag() -> u32 {
    loop {
        let tag = rand::random::<u32>();
        if tag != 0 {
            return tag;
        }
    }
}
