mod context_logger;
pub mod filter;

use futures;
use futures::sync::mpsc;
use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use std;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread::{self, JoinHandle};
use tokio_core::reactor::Core;

use self::filter::*;
use webrtc_sctp::stack::lowerlayer::{LowerLayer, LowerLayerPacket, LowerLayerProtocol};
use webrtc_sctp::stack::sync::SctpHandle;
use webrtc_sctp::stack::SctpStack;

const SCTP_UDP_TUNNELING_PORT: u16 = 9899;
#[allow(unused)]
const SCTP_UDP_TUNNELING_PORT_OUTGOING: u16 = 9900;

const IP_PREFIX: [u8; 3] = [10, 0, 0];

#[allow(unused)]
fn ip_to_index(ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            assert_eq!(octets[0], IP_PREFIX[0]);
            assert_eq!(octets[1], IP_PREFIX[1]);
            assert_eq!(octets[2], IP_PREFIX[2]);
            octets[3] as usize
        }
        _ => unreachable!(),
    }
}

fn index_to_ip(index: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        IP_PREFIX[0],
        IP_PREFIX[1],
        IP_PREFIX[2],
        index as u8,
    ))
}

pub struct Host {
    pub address: SocketAddr,
    pub handle: SctpHandle,
}

pub struct Simulation {
    pub hosts: Vec<Host>,
    thread: Option<JoinHandle<()>>,
    unused_ip: IpAddr,
    pause_command_tx: PauseCommandTx,
}

pub struct FlyingPacket {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub llp: LowerLayerPacket,
}

pub type PacketStream = Box<Stream<Item = FlyingPacket, Error = ()> + Send>;

impl FlyingPacket {
    #[allow(unused)]
    pub fn src_index(&self) -> usize {
        ip_to_index(self.src.ip())
    }

    #[allow(unused)]
    pub fn dst_index(&self) -> usize {
        ip_to_index(self.dst.ip())
    }

    fn is_data(&self) -> bool {
        let data = &self.llp.buffer[0..self.llp.length];
        let sctp_packet = ::webrtc_sctp::packet::parse(data).unwrap();
        sctp_packet.chunks.len() == 1 && match &sctp_packet.chunks[0] {
            &::webrtc_sctp::packet::chunk::Chunk::Data(_) => true,
            _ => false,
        }
    }
}

const SIMULATION_THREAD_NAME: &'static str = "simulation";

impl Simulation {
    pub fn new(num_hosts: usize) -> Simulation {
        Self::instantiate(num_hosts, vec![])
    }

    pub fn with_filters(num_hosts: usize, filters: Vec<FilterBox>) -> Simulation {
        Self::instantiate(num_hosts, filters)
    }

    fn instantiate(num_hosts: usize, filters: Vec<FilterBox>) -> Simulation {
        context_logger::log_init();
        let (tx, rx) = std::sync::mpsc::channel::<(Vec<Host>, IpAddr, PauseCommandTx)>();
        let mut log_context = 0;

        // Run the tokio event loop
        let thread = thread::Builder::new()
            .name(SIMULATION_THREAD_NAME.to_string())
            .spawn(move || {
                // Create the tokio event loop
                let mut core = Core::new().unwrap();

                // Spawn a "Pause" future that allows the simulation to be paused by
                // blocking event loop progress.
                let (pause_future, pause_command_tx) = Pause::new();
                core.handle().spawn(pause_future);

                // Spawn the router future
                let (mut router, lower_layers, unused_ip) = Router::new(num_hosts);
                for filter in filters {
                    router.add_filter(filter);
                }
                core.handle().spawn(router);

                let mut hosts = vec![];
                let mut sctp_futures = vec![];
                for lower_layer in lower_layers {
                    let address = lower_layer.address();
                    let sctp_stack = SctpStack::new_with_lower_layer(lower_layer);
                    hosts.push(Host {
                        address,
                        handle: sctp_stack.handle(),
                    });
                    let sctp_stack = context_logger::LogContextFuture::new(sctp_stack, log_context);
                    log_context += 1;
                    sctp_futures.push(sctp_stack);
                }

                // Supply host information to the main thread
                tx.send((hosts, unused_ip, pause_command_tx)).unwrap();

                // Run the futures
                let join_future = futures::future::join_all(sctp_futures);
                core.run(join_future).unwrap();
            }).unwrap();

        // Retrieve the provisioned hosts
        let (hosts, unused_ip, pause_command_tx) = rx.recv().unwrap();

        Simulation {
            hosts: hosts,
            thread: Some(thread),
            unused_ip,
            pause_command_tx,
        }
    }

    pub fn pause(&mut self) -> Resume {
        let (pause_done_tx, pause_done_rx): (PauseDoneTx, PauseDoneRx) = oneshot::channel::<()>();
        let (resume_tx, resume_rx): (ResumeTx, ResumeRx) = oneshot::channel::<()>();
        self.pause_command_tx
            .try_send((pause_done_tx, resume_rx))
            .unwrap();
        pause_done_rx.wait().unwrap();
        Resume { resume_tx }
    }

    pub fn unused_ip(&self) -> IpAddr {
        self.unused_ip
    }

    pub fn exit(&mut self) {
        trace!("Exiting Simulation...");
        if let Some(thread) = self.thread.take() {
            for host in self.hosts.iter_mut() {
                host.handle.exit().unwrap();
            }
            thread.join().unwrap();
        }
        trace!("Exit Simulation Done.");
    }
}

impl Drop for Simulation {
    fn drop(&mut self) {
        trace!("Dropping Simulation");
        self.exit();
    }
}

struct Router {
    incoming: Option<PacketStream>,
    host_map: HashMap<IpAddr, (usize, mpsc::UnboundedSender<LowerLayerPacket>)>,
}

impl Router {
    pub fn new(hosts: usize) -> (Router, Vec<Box<LowerLayer>>, IpAddr) {
        // TODO: testing
        //let filter: Option<FilterBox> = Some(Box::new(self::filter::DebugFilter::new()));

        // incoming (from the router's perspective)
        let (tx, rx) = mpsc::unbounded();

        let mut host_map = HashMap::new();
        let mut lower_layers = vec![];
        for i in 0..hosts {
            if i == std::u8::MAX as usize {
                panic!("simulation: too many hosts");
            }
            let host_address = index_to_ip(i);

            // outgoing (from the router's perspective)
            let (outgoing_tx, outgoing_rx) = mpsc::unbounded();

            let lower_layer: Box<LowerLayer> = Box::new(SimulationLowerLayer::new(
                tx.clone(),
                outgoing_rx,
                host_address,
            ));
            lower_layers.push(lower_layer);

            host_map.insert(host_address, (i, outgoing_tx));
        }

        // Record the "next ip" which does not have a simulated host.  This can be
        // used to test connecting to a non-existent host.
        let unused_ip = index_to_ip(hosts);

        let router = Router {
            incoming: Some(Box::new(rx)),
            host_map,
        };
        (router, lower_layers, unused_ip)
    }

    pub fn add_filter(&mut self, mut filter: FilterBox) {
        let previous_incoming: PacketStream = self.incoming.take().unwrap();
        filter.set_incoming_stream(previous_incoming);
        self.incoming = Some(Box::new(filter));
    }
}

impl Future for Router {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.incoming.as_mut().map(|s| s.poll()).unwrap() {
                Err(_) => return Err(()),
                Ok(Async::Ready(Some(FlyingPacket {
                    src,
                    dst: _,
                    llp: mut packet,
                }))) => {
                    let dst = packet.address;
                    //println!("router received {} bytes {}->{}", packet.length,src,dst);
                    packet.address = src;

                    match self.host_map.get(&dst.ip()) {
                        Some(&(_, ref tx)) => {
                            tx.unbounded_send(packet).unwrap();
                        }
                        None => {
                            // This can happen normally, as at least one test
                            // (test_connect_timeout()) intentionally sends to a non-existent host.
                            warn!(
                                "router: unknown host: {} -- dropping packet",
                                packet.address
                            );
                        }
                    }
                }
                Ok(Async::Ready(None)) => {
                    //println!("router: end of stream");
                    return Ok(Async::Ready(()));
                }
                Ok(Async::NotReady) => {
                    //println!("router: not ready");
                    return Ok(Async::NotReady);
                }
            }
        }
    }
}

struct SimulationLowerLayer {
    outgoing: mpsc::UnboundedSender<FlyingPacket>,
    incoming: mpsc::UnboundedReceiver<LowerLayerPacket>,
    address: SocketAddr,
}

impl SimulationLowerLayer {
    pub fn new(
        outgoing: mpsc::UnboundedSender<FlyingPacket>,
        incoming: mpsc::UnboundedReceiver<LowerLayerPacket>,
        address: IpAddr,
    ) -> SimulationLowerLayer {
        let address = SocketAddr::new(address, SCTP_UDP_TUNNELING_PORT);
        SimulationLowerLayer {
            outgoing,
            incoming,
            address,
        }
    }
}

impl LowerLayerProtocol for SimulationLowerLayer {
    fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Stream for SimulationLowerLayer {
    type Item = LowerLayerPacket;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<LowerLayerPacket>, io::Error> {
        match self.incoming.poll() {
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e))),
            Ok(Async::Ready(Some(packet))) => {
                //println!("host {} received {} bytes from {}", self.address, packet.length, packet.address);
                return Ok(Async::Ready(Some(packet)));
            }
            Ok(Async::Ready(None)) => {
                //println!("host: end of stream");
                return Ok(Async::Ready(None));
            }
            Ok(Async::NotReady) => {
                //println!("host: not ready");
                return Ok(Async::NotReady);
            }
        }
    }
}

impl Sink for SimulationLowerLayer {
    type SinkItem = LowerLayerPacket;
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        packet: LowerLayerPacket,
    ) -> StartSend<Self::SinkItem, Self::SinkError> {
        let flying_packet = FlyingPacket {
            src: self.address,
            dst: packet.address,
            llp: packet,
        };
        match self.outgoing.unbounded_send(flying_packet) {
            Ok(_) => Ok(AsyncSink::Ready),
            Err(_) => panic!("send error"),
        }
    }
    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

use futures::sync::oneshot;

type PauseDoneTx = oneshot::Sender<()>;
type PauseDoneRx = oneshot::Receiver<()>;
type ResumeTx = oneshot::Sender<()>;
type ResumeRx = oneshot::Receiver<()>;
type PauseCommand = (PauseDoneTx, ResumeRx);
type PauseCommandTx = mpsc::Sender<PauseCommand>;
type PauseCommandRx = mpsc::Receiver<PauseCommand>;

struct Pause {
    pause_command_rx: PauseCommandRx,
}

impl Pause {
    pub fn new() -> (Pause, PauseCommandTx) {
        let (tx, rx) = mpsc::channel::<PauseCommand>(0);
        (
            Pause {
                pause_command_rx: rx,
            },
            tx,
        )
    }
}

impl Future for Pause {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Ok(Async::Ready(Some(command))) = self.pause_command_rx.poll() {
            // Pause until the caller requests resume by firing the oneshot.
            let (pause_done_tx, resume_rx) = command;
            pause_done_tx.send(()).unwrap();
            resume_rx.wait().unwrap();
        };
        Ok(Async::NotReady)
    }
}

pub struct Resume {
    resume_tx: oneshot::Sender<()>,
}

impl Resume {
    pub fn resume(self) {
        self.resume_tx.send(()).unwrap();
    }
}
