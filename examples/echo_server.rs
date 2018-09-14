extern crate env_logger;
extern crate futures;
extern crate rand;
extern crate tokio_core;
extern crate tokio_timer;
extern crate webrtc_sctp;

use std::thread;
use tokio_core::reactor::Core;

use webrtc_sctp::error::SctpResult;
use webrtc_sctp::stack::sync::SctpHandle;
use webrtc_sctp::stack::SctpStack;

/// Generate padding bytes filled with decimal numbers indicating the buffer offset of the first
/// digit.  (This may be useful for debugging purposes.)
fn padding(length: usize) -> Vec<u8> {
    let mut position = 0;
    let mut vec = Vec::with_capacity(length);

    while position < length {
        let bytes_remaining = length - position;
        let mut tag = format!("{},", position).into_bytes();
        if tag.len() > bytes_remaining {
            // Not enough space for the tag; fill the last few bytes with 'x'
            tag.clear();
            for _ in 0..bytes_remaining {
                tag.push(b'x');
            }
        }
        position += tag.len();
        vec.extend(tag);
    }

    vec
}

fn main() {
    env_logger::init();
    let (tx, rx) = std::sync::mpsc::channel::<SctpHandle>();

    // Run the tokio event loop
    thread::spawn(move || {
        // Create the tokio event loop
        let mut core = Core::new().unwrap();

        // Create the SctpStack future
        let sctp_stack = SctpStack::new(core.handle());

        // Supply a handle to the main thread
        let handle = sctp_stack.handle();
        tx.send(handle).unwrap();

        // Run the future
        core.run(sctp_stack).unwrap();
    });

    // Retrieve the handle
    let handle = rx.recv().unwrap();

    if let Err(e) = echo_server(handle) {
        println!("error: {}", e);
    }
}

fn echo_server(mut handle: SctpHandle) -> SctpResult<()> {
    // Test parameters

    // Test connect
    //let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    //let test_destination = SocketAddr::new(localhost, 7);
    //let result = handle.connect(test_destination).unwrap();
    //thread::sleep(Duration::from_secs(3600));

    // Test listen
    let mut listener = handle.listen(2000).unwrap();
    let mut association = listener.accept();
    //println!("incoming association: {:?}", association);

    association.send_bytes(b"Hello, SCTP!\n".to_vec())?;
    loop {
        let msg = match association.recv() {
            Ok(Some(message)) => message,
            Ok(None) => {
                println!("Association closed.");
                break;
            }
            Err(e) => {
                println!("Association error: {}.", e);
                break;
            }
        };

        match &msg.buffer[..] {
            b"abort\n" => {
                println!("aborting...");
                association.abort()?;
                println!("abort done.");
                break;
            }
            b"shutdown\n" => {
                println!("shutting down...");

                // Request shutdown
                association.shutdown()?;

                // Eat data until the end of the stream.
                association.recv_wait()?;

                println!("shutdown done.");
                break;
            }
            _ => {}
        }

        let mut echo = vec![];
        echo.extend(padding(1000)); // padding to test fragmentation
        echo.extend(b"Echo: ".to_vec());
        echo.extend(&msg.buffer[..]);
        association.send_bytes(echo)?;
    }
    Ok(())
}
