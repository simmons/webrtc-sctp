extern crate blake2;
extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate rand;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;

extern crate webrtc_sctp;

mod simulation;

use blake2::{Blake2b, Digest};
use futures::sync::oneshot;
use futures::Future;
use rand::{Rng, RngCore, XorShiftRng};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use simulation::filter;
use simulation::Simulation;
use webrtc_sctp::error::{SctpError, SctpResult};
use webrtc_sctp::stack::association::AssociationCommand;
use webrtc_sctp::stack::sync::AssociationHandle;
use webrtc_sctp::stack::Timeout;
use webrtc_sctp::UserMessage;

const LISTEN_PORT: u16 = 2000;
const TIMEOUT_MS: u64 = 200;
const LONG_TIMEOUT_MS: u64 = 5000;

#[test]
fn test_associate() {
    let mut simulation = Simulation::new(2);

    // Server: Listen for incoming connections.
    let mut _listener = simulation.hosts[0].handle.listen(LISTEN_PORT).unwrap();

    // Client: Connect to server.
    let test_destination = SocketAddr::new(simulation.hosts[0].address.ip(), LISTEN_PORT);
    let mut _client_assn = simulation.hosts[1]
        .handle
        .connect(
            test_destination,
            Timeout::Some(Duration::from_millis(TIMEOUT_MS)),
        ).unwrap();
}

#[test]
fn test_shutdown() {
    let mut simulation = Simulation::new(2);

    // Server: Listen for incoming connections.
    let mut listener = simulation.hosts[0].handle.listen(LISTEN_PORT).unwrap();

    // Client: Connect to server.
    let test_destination = SocketAddr::new(simulation.hosts[0].address.ip(), LISTEN_PORT);
    let mut client_assn = simulation.hosts[1]
        .handle
        .connect(
            test_destination,
            Timeout::Some(Duration::from_millis(TIMEOUT_MS)),
        ).unwrap();

    // Server: Accept connection.
    let mut server_assn = listener.accept();

    // Client: Shutdown.
    client_assn.shutdown().unwrap();
    client_assn.recv_wait().unwrap();
    // Don't shutdown the server end... it will close when the client requests shutdown.
    // Simultaneous-shutdown will be tested in a separate test.
    // server_assn.shutdown();
    server_assn.recv_wait().unwrap();
}

#[test]
fn test_data() {
    let mut simulation = Simulation::new(2);

    // Server: Listen for incoming connections.
    let mut listener = simulation.hosts[0].handle.listen(LISTEN_PORT).unwrap();

    // Client: Connect to server.
    let test_destination = SocketAddr::new(simulation.hosts[0].address.ip(), LISTEN_PORT);
    let mut client_assn = simulation.hosts[1]
        .handle
        .connect(
            test_destination,
            Timeout::Some(Duration::from_millis(TIMEOUT_MS)),
        ).unwrap();

    // Server: Accept connection and say hello.
    let mut server_assn = listener.accept();
    let server_message = b"Hello from server!\n";
    server_assn.send_bytes(server_message.to_vec()).unwrap();

    // Client: Say hello right back.
    let client_message = b"Hello from client!\n";
    client_assn.send_bytes(client_message.to_vec()).unwrap();

    // Server: Receive and verify the client's message.
    let message = server_assn.recv().unwrap().unwrap();
    assert_eq!(message.buffer, client_message);

    // Client: Receive and verify the server's message.
    let message = client_assn.recv().unwrap().unwrap();
    assert_eq!(message.buffer, server_message);

    // Shutdown
    client_assn.shutdown().unwrap();
    client_assn.recv_wait().unwrap();
    server_assn.recv_wait().unwrap();
}

// Enqueue shutdown commands for two associations while the simulation is paused to reproduce a
// simultaneous shutdown scenario.
pub fn simultaneous_shutdown(
    simulation: &mut Simulation,
    a1: &mut AssociationHandle,
    a2: &mut AssociationHandle,
) -> SctpResult<()> {
    let (a1_return_tx, a1_return_rx) = oneshot::channel::<SctpResult<()>>();
    let (a2_return_tx, a2_return_rx) = oneshot::channel::<SctpResult<()>>();

    let resume = simulation.pause();

    match a1
        .command()
        .try_send(AssociationCommand::Shutdown(a1_return_tx))
    {
        Ok(_) => {}
        Err(ref e) if e.is_full() => return Err(SctpError::CommandQueueFull),
        Err(ref e) if e.is_disconnected() => return Err(SctpError::Closed),
        Err(_) => return Err(SctpError::BadState),
    };
    match a2
        .command()
        .try_send(AssociationCommand::Shutdown(a2_return_tx))
    {
        Ok(_) => {}
        Err(ref e) if e.is_full() => return Err(SctpError::CommandQueueFull),
        Err(ref e) if e.is_disconnected() => return Err(SctpError::Closed),
        Err(_) => return Err(SctpError::BadState),
    };

    resume.resume();

    match a1_return_rx.wait() {
        Ok(_) => {}
        Err(_) => return Err(SctpError::Closed),
    };
    match a2_return_rx.wait() {
        Ok(_) => {}
        Err(_) => return Err(SctpError::Closed),
    };
    Ok(())
}

#[test]
fn test_simultaneous_shutdown() {
    let mut simulation = Simulation::new(2);

    // Server: Listen for incoming connections.
    let mut listener = simulation.hosts[0].handle.listen(LISTEN_PORT).unwrap();

    // Client: Connect to server.
    let test_destination = SocketAddr::new(simulation.hosts[0].address.ip(), LISTEN_PORT);
    let mut client_assn = simulation.hosts[1]
        .handle
        .connect(
            test_destination,
            Timeout::Some(Duration::from_millis(TIMEOUT_MS)),
        ).unwrap();

    // Server: Accept connection and say hello.
    let mut server_assn = listener.accept();

    // Have both endpoints initiate shutdown at the same time.
    simultaneous_shutdown(&mut simulation, &mut client_assn, &mut server_assn).unwrap();

    // Consume the associations until they are closed.
    client_assn.recv_wait().unwrap();
    server_assn.recv_wait().unwrap();
}

#[test]
fn test_connect_timeout() {
    let mut simulation = Simulation::new(2);
    let unused_ip = simulation.unused_ip();

    // Server: Listen for incoming connections.
    let _listener = simulation.hosts[0].handle.listen(LISTEN_PORT).unwrap();

    // Client: Try to connect to a non-existent host with a timeout.
    let test_destination = SocketAddr::new(unused_ip, LISTEN_PORT);
    use std::time::Duration;
    let connect_result = simulation.hosts[1].handle.connect(
        test_destination,
        Timeout::Some(Duration::from_millis(TIMEOUT_MS)),
    );
    assert!(match connect_result {
        Ok(_) => false,
        Err(SctpError::Timeout) => true,
        Err(_) => false,
    });

    // Client: Try to connect to the server with a timeout.
    let test_destination = SocketAddr::new(simulation.hosts[0].address.ip(), LISTEN_PORT);
    let connect_result = simulation.hosts[1].handle.connect(
        test_destination,
        Timeout::Some(Duration::from_millis(TIMEOUT_MS)),
    );
    assert!(match connect_result {
        Ok(_) => true,
        Err(SctpError::Timeout) => false,
        Err(_) => false,
    });
}

#[test]
fn test_recv_timeout() {
    let mut simulation = Simulation::new(2);

    // Server: Listen for incoming connections.
    let mut listener = simulation.hosts[0].handle.listen(LISTEN_PORT).unwrap();

    // Client: Connect to the server.
    let test_destination = SocketAddr::new(simulation.hosts[0].address.ip(), LISTEN_PORT);
    let mut client_assn = simulation.hosts[1]
        .handle
        .connect(test_destination, Timeout::Default)
        .unwrap();

    // Server: Accept connection.
    let _server_assn = listener.accept();

    // Set a timeout on the client
    client_assn
        .set_recv_timeout(Timeout::Some(Duration::from_millis(TIMEOUT_MS)))
        .unwrap();

    // Client: Wait for a message that never comes.
    let recv_result = client_assn.recv();
    assert!(match recv_result {
        Ok(_) => false,
        Err(SctpError::Timeout) => true,
        Err(_) => false,
    });
}

fn deterministic_rng() -> XorShiftRng {
    const SEED: [u8; 16] = [
        0x04, 0xC1, 0x1D, 0xB7, 0x1E, 0xDC, 0x6F, 0x41, 0x74, 0x1B, 0x8C, 0xD7, 0x32, 0x58, 0x34,
        0x99,
    ];
    rand::SeedableRng::from_seed(SEED)
}

fn random_message(rng: &mut XorShiftRng, min_size: usize, max_size: usize) -> UserMessage {
    // Create a random buffer
    let size = rng.gen::<usize>() % (max_size - min_size) + min_size;
    let mut buffer: Vec<u8> = vec![0; size];
    rng.fill_bytes(&mut buffer);

    // Create a message
    UserMessage::new(false, 0, 0, buffer)
}

#[test]
fn test_single_fragmented_message() {
    let mut rng = deterministic_rng();
    let message = random_message(&mut rng, 2 * 1024, 32 * 1024);
    let mut simulation = Simulation::new(2);

    // Server: Listen for incoming connections.
    let mut listener = simulation.hosts[0].handle.listen(LISTEN_PORT).unwrap();

    // Client: Connect to server.
    let test_destination = SocketAddr::new(simulation.hosts[0].address.ip(), LISTEN_PORT);
    let mut client_assn = simulation.hosts[1]
        .handle
        .connect(
            test_destination,
            Timeout::Some(Duration::from_millis(TIMEOUT_MS)),
        ).unwrap();

    // Server: Accept connection and send message.
    let mut server_assn = listener.accept();
    server_assn.send(message.clone()).unwrap();

    // Client: Receive and verify the server's message.
    let received_message = client_assn.recv().unwrap().unwrap();
    assert_eq!(received_message.buffer, message.buffer);

    // Shutdown
    client_assn.shutdown().unwrap();
    client_assn.recv_wait().unwrap();
    server_assn.recv_wait().unwrap();
}

#[test]
fn test_many_fragmented_messages() {
    const MESSAGE_COUNT: usize = 256;
    let mut rng = deterministic_rng();
    let mut simulation = Simulation::new(2);

    // Server: Listen for incoming connections.
    let mut listener = simulation.hosts[0].handle.listen(LISTEN_PORT).unwrap();

    // Client: Connect to server.
    let test_destination = SocketAddr::new(simulation.hosts[0].address.ip(), LISTEN_PORT);
    let mut client_assn = simulation.hosts[1]
        .handle
        .connect(
            test_destination,
            Timeout::Some(Duration::from_millis(TIMEOUT_MS)),
        ).unwrap();

    // Server: Accept connection
    let mut server_assn = listener.accept();

    // Start a server thread to send messages, returning a hash of the buffer data.
    let server_thread = thread::spawn(move || {
        server_assn
            .set_send_timeout(Timeout::Some(Duration::from_millis(LONG_TIMEOUT_MS)))
            .unwrap();
        let mut hasher = Blake2b::new();
        for _ in 0..MESSAGE_COUNT {
            let message = random_message(&mut rng, 2 * 1024, 32 * 1024);
            hasher.input(&message.buffer);
            server_assn.send(message).unwrap();
        }
        server_assn.shutdown().unwrap();
        server_assn.recv_wait().unwrap();
        hasher.result().to_vec()
    });

    // Start a client thread to receive messages, returning a hash of the buffer data.
    let client_thread = thread::spawn(move || {
        client_assn
            .set_recv_timeout(Timeout::Some(Duration::from_millis(LONG_TIMEOUT_MS)))
            .unwrap();
        let mut hasher = Blake2b::new();
        loop {
            match client_assn.recv() {
                Ok(Some(message)) => {
                    hasher.input(&message.buffer);
                }
                Ok(None) => break,
                Err(e) => panic!("unexpected error: {}", e),
            }
        }
        hasher.result().to_vec()
    });

    let server_hash = server_thread.join().unwrap();
    let client_hash = client_thread.join().unwrap();
    assert_eq!(server_hash, client_hash);
}

#[ignore]
#[test]
fn test_many_associate_shutdown() {
    const ITERATIONS: usize = 100000;
    let mut simulation = Simulation::new(2);

    // Server: Listen for incoming connections.
    let mut listener = simulation.hosts[0].handle.listen(LISTEN_PORT).unwrap();

    for _ in 0..ITERATIONS {
        // Client: Connect to server.
        let test_destination = SocketAddr::new(simulation.hosts[0].address.ip(), LISTEN_PORT);
        let mut client_assn = simulation.hosts[1]
            .handle
            .connect(
                test_destination,
                Timeout::Some(Duration::from_millis(TIMEOUT_MS)),
            ).unwrap();

        // Server: Accept connection.
        let mut server_assn = listener.accept();

        // Client: Shutdown.
        client_assn.shutdown().unwrap();
        client_assn.recv_wait().unwrap();
        // Don't shutdown the server end... it will close when the client requests shutdown.
        // Simultaneous-shutdown will be tested in a separate test.
        // server_assn.shutdown();
        server_assn.recv_wait().unwrap();
    }
}

#[test]
fn test_retransmit() {
    let message = UserMessage::new(false, 0, 0, b"testing123".to_vec());
    let mut simulation = Simulation::with_filters(2, vec![Box::new(filter::NthDropFilter::new(1))]);

    // Server: Listen for incoming connections.
    let mut listener = simulation.hosts[0].handle.listen(LISTEN_PORT).unwrap();

    // Client: Connect to server.
    let test_destination = SocketAddr::new(simulation.hosts[0].address.ip(), LISTEN_PORT);
    let mut client_assn = simulation.hosts[1]
        .handle
        .connect(
            test_destination,
            Timeout::Some(Duration::from_millis(TIMEOUT_MS)),
        ).unwrap();

    // Set a timeout on the client
    client_assn
        .set_recv_timeout(Timeout::Some(Duration::from_millis(LONG_TIMEOUT_MS)))
        .unwrap();

    // Server: Accept connection and send message.
    let mut server_assn = listener.accept();
    server_assn.send(message.clone()).unwrap();

    // Client: Receive and verify the server's message.
    let received_message = client_assn.recv().unwrap().unwrap();
    assert_eq!(received_message.buffer, message.buffer);

    // Shutdown
    client_assn.shutdown().unwrap();
    client_assn.recv_wait().unwrap();
    server_assn.recv_wait().unwrap();
}
