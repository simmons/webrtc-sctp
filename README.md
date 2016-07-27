webrtc-sctp: A pure-Rust userspace SCTP implementation
======================================================================

Work In Progress
----------------------------------------

This crate is a work in progress.  The existing features may be
minimally implemented and not in compliance with the SCTP specification,
while other mandatory features may not be implemented at all. Unless you
are interested in contributing to the stack, you are urged to avoid
using this code in either a production or a development environment at
this time.  (Until congestion control is properly implemented, it may
actually be harmful to networks.)


Goal
----------------------------------------

The goal is to develop a simple pure-Rust user-space SCTP stack that
provides the minimal feature set needed to implement WebRTC data
channels.


Background
----------------------------------------

Peer-to-peer networking has been used to good effect over the past 20
years to improve services such as audio/video conferencing, online
gaming, and overlay networks, in spite of NAT traversal requiring exotic
techniques and reinventing the universe on top of UDP.  WebRTC is an
IETF standard that bundles together the best-known methods and several
pre-existing standards for peer-to-peer networking to provide a common
target for interoperability.  Non-media data channels between peers are
based on the Stream Control Transport Protocol (SCTP), a "better TCP"
originally invented by the telecommunications industry.  However,
implementing transport protocols is difficult enough that most (all?)
implementations of WebRTC data channels re-use the same C library for
SCTP.  I think it would be interesting and educational to develop an
SCTP implementation, and eventually a full WebRTC stack, in pure Rust.
This would not only provide a second option for application developers,
but expand the ecosystem of network building blocks implemented in a
safe programming language.

My SCTP implementation is based on Tokio and provides an asynchronous
API using futures-based MPSC command queues to open/close associations,
configure streams, etc.  A synchronous API wraps the asynchronous API
for convenience and ease of testing by running the Tokio reactor in its
own thread.  Support for a configurable lower-layer protocol allows
SCTP-over-UDP for testing interoperability with `libusrsctp`, SCTP over
an in-process switching layer to allow for network simulations in
integration tests, and eventually SCTP-over-DTLS for WebRTC data
channels.  My general development strategy is to avoid early
optimization until the SCTP state machine is complete and functional.
In addition to hunting down needless Box's and clone()'s, there are many
design choices that will need to be reassessed.  Is Nom really an
efficient way to parse packets?  Is std::collections::BinaryHeap really
the best way to implement an ordered reassembly queue?  The complex
nature of transport protocols allows for a great many bugs that the Rust
compiler can't save us from, so testing and debugging will likely be a
major effort even after functional completion.  Additionally, stress
testing has revealed at least one race condition in a dependency
(futures::sync::mpsc) that will need to be addressed.  The
implementation is developed to a point where short messages can be
passed back and forth, but work on some critical functionality (e.g.
congestion control, MTU probing) is still in progress.


Motivation
----------------------------------------

1. My personal motivation for this work is to become more proficient in
   Rust by developing a non-trivial software library, and also gain more
   exposure to the details of developing network transport layers.
2. Most of the world (at least Chrome, Firefox, and the FreeBSD kernel)
   seems to re-use [the same SCTP
   stack](https://github.com/sctplab/usrsctp), written in C.  While it's
   great to have such a gold standard, there is value in increasing
   implementation diversity with an independent library.
3. While the current proof-of-concept code is a long way from being
   efficient or reliable, the constrained feature set could some day,
   for certain use cases, yield a tighter, more efficient implementation
   with a smaller footprint and attack surface.
4. Peer-to-peer software is a research interest of mine, and I'd love to
   see some basic building blocks enabling Rust programmers to easily
   experiment with new ideas using an open standard like WebRTC Data
   Channels.


Anti-motivation
----------------------------------------

1. Implementing a network transport protocol like SCTP involves a huge
   number of moving parts that must all work seamlessly together, making
   this a fairly involved project.  If I realized how much work it would
   be, I might have settled on some other project.
2. Research into network protocols has picked up considerably in recent
   years, and it's possible that SCTP may some day be superseded by a
   more modern protocol like QUIC.  There is currently talk about QUIC
   becoming a first-class WebRTC transport, although it seems to lack
   explicit support for unordered/unreliable delivery, so it may not be
   a 100% drop-in replacement for SCTP in WebRTC data channels.


Remaining tasks
----------------------------------------

- [ ] Remaining retransmission tasks
    - [ ] When a TSN previously acknowledged in a gap ack block is no
          longer acknowledged (i.e. it was dropped by the peer), then
          start the timer.
    - [ ] Update congestion control as needed -- adjust `ssthresh`
          according to Section 7.2.3, and set `cwnd` to the MTU.
- [ ] Congestion control
- [ ] Periodic heartbeats
- [ ] Path MTU probing
- [ ] Delayed SACK
- [ ] Exceptional conditions:
    - [ ] Better error returns
    - [ ] Send ABORTs when needed
    - [ ] Handle ABORTS
        - [ ] Close association, notify application layer
    - [ ] Send/handle ERROR
    - [ ] Handle Out-Of-The-Blue (OOTB) packets
- [ ] Implement SCTP extensions required for full compliance with the
      WebRTC data channel standards:
    - [ ] RFC 3758: SCTP Partial Reliability Extension
    - [ ] RFC 7496: Additional Policies for the Partially Reliable SCTP
          Extension (in particular, the limited retransmission policy)
    - [ ] RFC 6525: SCTP Stream Reconfiguration (for closing channels)
    - [ ] RFC 5061: Dynamic Address Reconfiguration (partial -- only
          used to signal support for the stream reset extension)
    - [ ] RFC 4820: Padding Chunk and Parameter for SCTP (for Path MTU
          probing)
    - [ ] RFC 8260: Stream Schedulers and User Message Interleaving for
          SCTP (This is a "SHOULD")
- [ ] Upgrade to latest dependencies
    - [ ] Tokio-core is deprecated and should be replaced with tokio.
        - [ ] Think about the proper way of handling the SctpStack
              lifecycle.  The impetus is partially due to the new
              default `tokio::run()` reactor behavior of terminating
              when all tasks are complete instead of when the main
              future completes.  But we also need to consider how
              SctpStack works as a component within larger network
              machinery.  (Since we don't spawn any tasks at present,
              maybe there's nothing to do?)
    - [ ] Tokio-timer should be upgraded.  (Use Tokio's embedded
          `tokio::timer` instead of upgrading the crate dependency
          directly.)
        - [ ] Update the retransmission code's `CLOCK_GRANULARITY_NS` to
              reflect the finer clock granularity.
- [ ] Test/simulation tasks
    - [ ] Test lots of associate+shutdown steps
    - [ ] Test dropped packets & out-of-order (not random delay) packets
    - [ ] Test large streams in ideal conditions
    - [ ] Test large streams in hostile conditions (drop, delay, OoO,
          etc.)
    - [ ] Devise a means of testing congestion control.
    - [ ] Test Path MTU probing.
- [ ] Revisit design decisions
    - [ ] Is `nom` the best way to parse packets?  Should we even be
          trying to parse packets at all, rather than just using the
          data fields in-place (converting from big endian as needed)?
    - [ ] Reconsider the buffer management strategies.  Are there ways
          of reducing copies?
- [ ] Optimizations
    - [ ] Consider alternatives for cases where `Box` and `.clone()` are
          used.
    - [ ] Remove (or document) `unwrap()`'s.
    - [ ] Implement benchmarks to find more opportunities for
          optimization.
- [ ] Evaluate additional features for possible implementation
    - [ ] Partial Delivery API
- [ ] A considerable amount of additional testing, debugging, and
      optimization.  In particular, we are looking for:
    - [ ] Discovery and elimination of potential deadlock conditions
        - [ ] Could this happen when we receive a message that is larger
              than the recv buffer size?
    - [ ] Correctness with regards to the specifications.  This will
          require quite a bit of code auditing.
    - [ ] Discovery and removal of bugs.
    - [ ] Efficiency.


Living with Path MTU
----------------------------------------

A classic problem we encounter when developing network transports is
deciding how large of a packet we can send to a peer, without triggering
IP fragmentation which is best avoided.  Each network link may have a
different maximum transmission unit (MTU), and discovering the Path MTU
(the lowest MTU of all the links between us and our peer) can be quite
an involved task.

Traditionally, Path MTU is determined by setting the don't fragment (DF)
bit on transmitted IP packets, and listening for ICMP messages
indicating that the packets are too large.  This isn't suitable for our
SCTP stack for the following reasons:

1. Even in the conventional case of SCTP-over-IP (or even TCP-over-IP),
   hostile networks can prevent these ICMP messages from being generated
   or routed.  This is known as the Path MTU Black Hole problem.

2. Since our SCTP is expected to live further up the stack (e.g.  in the
   WebRTC data channel case, SCTP-over-DTLS-over-UDP-over-IP), it
   becomes problematic to implement ICMP-based Path MTU discovery at the
   SCTP layer.

3. Listening for ICMP messages associated with a UDP socket is a
   platform-specific problem.  Linux provides a facility for this
   (IP_MTU_DISCOVER), but it's not clear how much work would be required
   (or even if it's possible) to support this in a cross-platform
   fashion. (Mio does not currently provide a cross-platform means of
   setting DF.)

4. The WebRTC Data Channel specification explicitly gives up on an ICMP
   method in favor of probing:

> Incoming ICMP or ICMPv6 messages can't be processed by the SCTP
> layer, since there is no way to identify the corresponding
> association.  Therefore SCTP MUST support performing Path MTU
> discovery without relying on ICMP or ICMPv6 as specified in [RFC4821]
> using probing messages specified in [RFC4820].  The initial Path MTU
> at the IP layer SHOULD NOT exceed 1200 bytes for IPv4 and 1280 for
> IPv6.

We should implement RFC4820/RFC4821 Path MTU probing.  For reference,
the `libusrsctp` approach is to start with the local network interface's
MTU and step up or down a fixed list of 18 common MTUs.  (We'd start
with 1200 or 1280 to comply with WebRTC, of course.)


Shortcomings
----------------------------------------

The first version of this library will have a number of notable
shortcomings.

SCTP shortcomings:
- We do not implement any features related to multi-homing, as
  multi-homing is not required for WebRTC data channels.
- Limited configurability from the application-layer.
- No Partial Delivery API.
- We're not currently supporting any specific API guidelines (e.g.
  Sockets API or the SCTP "Interface with Upper Layer" API from RFC
  4960).

Performance sacrifices:
- Lots of clones and moves.  While we make use of a simple
  reference-counted shared buffer scheme for payloads, the end-to-end
  data path needs to be audited for needless copies.
- We stick to the collection types available in the Rust standard
  library, even where custom algorithms could perform better.  (And even
  some of the standard collections/algorithms used may be poor choices
  and need to be revisited.)
- In the UDP lower layer protocol, sending and receiving UDP datagrams
  using the standard `sendto()` and `recvfrom()` system calls means a
  context switch to and from kernel-mode for each and every packet,
  which could add considerable overhead to high-volume streams.  Linux
  supports `sendmmsg()` and `recvmmsg()` system calls to send and
  receive multiple datagrams at once, and perhaps other operating
  systems have a similar feature.  However, Mio does not currently
  expose such a feature.


Reference
----------------------------------------

WebRTC:
* [WebRTC Data Channels (draft-ietf-rtcweb-data-channel-13.txt)](https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13)

Major stack components:
* [RFC 4960: Stream Control Transmission Protocol](https://tools.ietf.org/html/rfc4960)
* [RFC 4347: Datagram Transport Layer Security Version 1.0](https://tools.ietf.org/html/rfc4347)
* [RFC 6347: Datagram Transport Layer Security Version 1.2](https://tools.ietf.org/html/rfc6347)
* [RFC 8261: Datagram Transport Layer Security (DTLS) Encapsulation of SCTP Packets](https://tools.ietf.org/html/rfc8261)
* [RFC 5245: Interactive Connectivity Establishment (ICE)](https://tools.ietf.org/html/rfc5245)

Associated standards:
* [WebRTC Data Channel Establishment Protocol (draft-ietf-rtcweb-data-protocol-09)](https://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-09)
* [RFC 5764: DTLS Extension to Establish Keys for SRTP](https://tools.ietf.org/html/rfc5764)

SCTP extensions:
* [RFC 3758: SCTP Partial Reliability Extension](https://tools.ietf.org/html/rfc3758)
* [RFC 7496: Additional Policies for the Partially Reliable SCTP Extension](https://tools.ietf.org/html/rfc7496) (in particular, the limited retransmission policy)
* [RFC 6525: SCTP Stream Reconfiguration](https://tools.ietf.org/html/rfc6525) (for closing channels)
* [RFC 5061: Dynamic Address Reconfiguration)](https://tools.ietf.org/html/rfc5061) (partial -- only used to signal the support of the stream reset extension)
* [RFC 4820: Padding Chunk and Parameter for SCTP](https://tools.ietf.org/html/rfc4820) and
  [RFC 4821: Packetization Layer Path MTU Discovery](https://tools.ietf.org/html/rfc4821) (for Path MTU probing)
* [RFC 8260: Stream Schedulers and User Message Interleaving for SCTP](https://tools.ietf.org/html/rfc8260) ("SHOULD")


License
----------------------------------------

This crate is distributed under the terms of both the MIT license and
the Apache License (Version 2.0).  See LICENSE-MIT and LICENSE-APACHE
for details.

#### Contributing

Unless you explicitly state otherwise, any contribution you
intentionally submit for inclusion in the work, as defined in the
Apache-2.0 license, shall be dual-licensed as above, without any
additional terms or conditions.
