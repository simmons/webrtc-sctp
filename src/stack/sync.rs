//! Provide a synchronous API which wraps the asynchronous API to provide a convenient way of using
//! the SCTP stack.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize,Ordering};

use futures::sync::mpsc;
use futures::sync::oneshot;
use futures::{self, Future, Stream};

use error::{SctpError, SctpResult};
use packet::{SSN, TSN};
use stack::association::{AcceptQueueReceiver, AssociationCommand, AssociationCommandSender};
use stack::SctpCommand;
use stack::Timeout;
use UserMessage;

#[derive(Clone, Debug)]
pub struct SctpHandle {
    command_tx: mpsc::Sender<SctpCommand>,
}

impl SctpHandle {
    pub fn new(tx: mpsc::Sender<SctpCommand>) -> SctpHandle {
        SctpHandle { command_tx: tx }
    }

    fn send_cmd<T>(&mut self, cmd: SctpCommand, return_rx: oneshot::Receiver<T>) -> SctpResult<T> {
        match self.command_tx.try_send(cmd) {
            Ok(_) => {}
            Err(ref e) if e.is_full() => return Err(SctpError::CommandQueueFull),
            Err(ref e) if e.is_disconnected() => return Err(SctpError::Closed),
            Err(_) => return Err(SctpError::BadState),
        };
        match return_rx.wait() {
            Ok(item) => Ok(item),
            Err(_) => Err(SctpError::Closed),
        }
    }

    pub fn connect(
        &mut self,
        destination: SocketAddr,
        timeout: Timeout,
    ) -> SctpResult<AssociationHandle> {
        let (return_tx, return_rx) =
            oneshot::channel::<SctpResult<mpsc::Sender<AssociationCommand>>>();
        let association_command_tx = self.send_cmd(
            SctpCommand::Connect(destination, timeout, return_tx),
            return_rx,
        )??;
        Ok(AssociationHandle::new(association_command_tx, None))
    }

    pub fn listen(&mut self, port: u16) -> SctpResult<AssociationHandle> {
        let (return_tx, return_rx) =
            oneshot::channel::<(AssociationCommandSender, AcceptQueueReceiver)>();
        let (association_command_tx, accept_queue_rx) =
            self.send_cmd(SctpCommand::Listen(port, return_tx), return_rx)?;
        Ok(AssociationHandle::new(
            association_command_tx,
            Some(accept_queue_rx),
        ))
    }

    pub fn exit(&mut self) -> SctpResult<()> {
        let (return_tx, return_rx) = oneshot::channel::<()>();
        self.send_cmd(SctpCommand::Exit(return_tx), return_rx)
    }
}

#[derive(Debug)]
pub struct AssociationHandle {
    command_tx: mpsc::Sender<AssociationCommand>,
    accept_queue: Option<futures::stream::Wait<AcceptQueueReceiver>>,
    closed: bool,
    count: Arc<AtomicUsize>,
}

impl AssociationHandle {
    fn new(
        command_tx: mpsc::Sender<AssociationCommand>,
        accept_queue_rx: Option<AcceptQueueReceiver>,
    ) -> AssociationHandle {
        AssociationHandle {
            command_tx,
            accept_queue: accept_queue_rx.map(|rx| rx.wait()),
            closed: false,
            count: Arc::new(AtomicUsize::new(1)),
        }
    }

    fn send_cmd<T>(
        &mut self,
        cmd: AssociationCommand,
        return_rx: oneshot::Receiver<T>,
    ) -> SctpResult<T> {
        match self.command_tx.try_send(cmd) {
            Ok(_) => {}
            Err(ref e) if e.is_full() => return Err(SctpError::CommandQueueFull),
            Err(ref e) if e.is_disconnected() => return Err(SctpError::Closed),
            Err(_) => return Err(SctpError::BadState),
        };
        match return_rx.wait() {
            Ok(item) => Ok(item),
            Err(_) => Err(SctpError::Closed),
        }
    }

    pub fn command(&self) -> mpsc::Sender<AssociationCommand> {
        self.command_tx.clone()
    }

    pub fn accept(&mut self) -> AssociationHandle {
        match self.accept_queue {
            Some(ref mut q) => {
                match q.next() {
                    Some(Ok(new_command_tx)) => AssociationHandle::new(new_command_tx, None),
                    Some(Err(_)) => unreachable!(), // TODO: handle stream error
                    None => unreachable!(),         // TODO: handle listener close
                }
            }
            None => unreachable!(), // TODO: return error result instead
        }
    }

    pub fn send(&mut self, message: UserMessage) -> SctpResult<()> {
        let (return_tx, return_rx) = oneshot::channel::<SctpResult<()>>();
        let result = self.send_cmd(AssociationCommand::Send(message, return_tx), return_rx)?;
        result
    }

    pub fn send_bytes(&mut self, buffer: Vec<u8>) -> SctpResult<()> {
        let message = UserMessage {
            tsn: TSN::new(0),
            unordered: false,
            stream_id: 0,
            ssn: SSN::new(0),
            payload_protocol_id: 0,
            buffer: buffer,
        };
        self.send(message)
    }

    pub fn recv(&mut self) -> SctpResult<Option<UserMessage>> {
        let (return_tx, return_rx) = oneshot::channel::<SctpResult<Option<UserMessage>>>();
        match self.send_cmd(AssociationCommand::Recv(return_tx), return_rx) {
            Ok(Ok(m)) => Ok(m),
            Ok(Err(e)) => Err(e),
            // Map the Closed error to Ok(None) to indicate end-of-stream.
            Err(SctpError::Closed) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Eat data until the end of the stream is reached.  This is primarily intended for testing.
    pub fn recv_wait(&mut self) -> SctpResult<()> {
        loop {
            match self.recv() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn abort(&mut self) -> SctpResult<()> {
        let (return_tx, return_rx) = oneshot::channel::<()>();
        self.send_cmd(AssociationCommand::Abort(return_tx), return_rx)
    }

    pub fn shutdown(&mut self) -> SctpResult<()> {
        let (return_tx, return_rx) = oneshot::channel::<SctpResult<()>>();
        let result = self.send_cmd(AssociationCommand::Shutdown(return_tx), return_rx)?;
        result
    }

    pub fn set_recv_timeout(&mut self, timeout: Timeout) -> SctpResult<()> {
        let (return_tx, return_rx) = oneshot::channel::<()>();
        self.send_cmd(
            AssociationCommand::SetRecvTimeout(timeout, return_tx),
            return_rx,
        )
    }

    pub fn set_send_timeout(&mut self, timeout: Timeout) -> SctpResult<()> {
        let (return_tx, return_rx) = oneshot::channel::<()>();
        self.send_cmd(
            AssociationCommand::SetSendTimeout(timeout, return_tx),
            return_rx,
        )
    }
}

impl Clone for AssociationHandle {
    /// Clone an `AssociationHandle`.  Clones don't have an accept queue, so cannot `accept()`, but
    /// otherwise should be functional.
    fn clone(&self) -> Self {
        self.count.fetch_add(1, Ordering::SeqCst);
        AssociationHandle {
            command_tx: self.command_tx.clone(),
            accept_queue: None,
            closed: self.closed,
            count: self.count.clone(),
        }
    }
}

impl Drop for AssociationHandle {
    fn drop(&mut self) {
        let count = self.count.fetch_sub(1, Ordering::SeqCst) - 1;
        if count == 0 {
            self.abort().unwrap_or(());
        }
    }
}
