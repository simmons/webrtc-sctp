//! Retransmission is covered in section 6.3 of RFC 4960.
//!
//! 1. Perform round-trip time (RTT) measurements from the time a TSN is sent until it is
//!    acknowledged.
//!    a) A measurement must be made once per round-trip, but no more.  I interpret this to mean
//!       that only one measurement may be in progress at a time.
//!    b) Measurements must not be made on retransmissions.  If the TSN being measured is
//!       retransmitted, the measurement must be aborted.
//! 2. Adjust the retransmission timeout (RTO) after every measurement is concluded.
//!    a) Use the specified smoothing algorithm to calculate a new RTO.
//!    b) Clamp the new RTO to RTO.Min .. Option<RTO.Max>
//!    c) If RTTVAR is zero, increase it to the clock granularity.
//! 3. Manage the retransmission timer ("T3-rtx").
//!    R1) On any DATA send, if the timer is not running, start the timer with RTO.
//!    R2) If all outstanding data has been acknowledged, then cancel the timer.
//!    R3) If the earliest outstanding TSN is acknowledged, then restart the timer.
//! // TODO:
//!    R4) When a TSN previously acknowledged in a gap ack block is no longer acknowledged (e.g. it
//!        was dropped by the peer), then start the timer.
//! 4. Handle timer expiration.
//!    // TODO:
//!    E1) Update congestion control as needed.
//!       - adjust ssthresh according to Section 7.2.3
//!       - set cwnd to the MTU
//!    E2) Double RTO up to RTO.Max to provide back-off.
//!    E3) Retransmit as many of the earliest DATA chunks as will fit into a single packet based on
//!        the MTU.
//!        - Any remaining DATA chunks should be "marked for retransmission" and sent as soon as
//!          cwnd allows.
//!    E4) Restart the timer according to (R1) above.

use std::time::{Duration, Instant};

use tokio_timer;

use super::Association;
use packet::chunk::{Chunk, GapAckBlock};
use packet::TSN;
use stack::settings::DEFAULT_SCTP_PARAMETERS;

/// The retransmission state that will be embedded in every association.
pub struct State {
    pub timer: Option<tokio_timer::Sleep>,
    pub measurements: Measurements,
    pub tx_high_water_mark: TSN,
}

impl State {
    pub fn new(tx_high_water_mark: TSN) -> State {
        State {
            timer: None,
            measurements: Measurements::new(),
            tx_high_water_mark,
        }
    }
}

/// Use a trait to add retransmission functionality to Association.
///
/// This is awkward, but there really is a huge amount of state in an association, with many parts
/// interdependent on many other parts.  This makes it difficult to cleanly separate concerns such
/// as retransmission in an obvious and simple way.  (I.e. without a lot of Rc<RefCell<_>>, for
/// instance.)
///
/// Most C network stack implementations I've seen just interleave all the concerns together, and
/// (in my opinion) this reduces the readability.  So we can at least put retransmission concerns
/// in a different source file, even if doing so is only cosmetic.
///
/// We could also have just added more inherent methods to Association here, but I'm hoping that
/// using a trait is more clear.
pub trait Retransmission {
    fn on_outgoing_data(&mut self, chunk_tsn: TSN);
    fn on_cumulative_ack(&mut self, cumulative_tsn_ack: TSN, earliest_outstanding_tsn: Option<TSN>);
    fn on_gap_ack_block(&mut self, start: TSN, end: TSN); // TODO remove
    fn on_gap_ack_blocks(&mut self, cumulative_tsn_ack: TSN, gap_ack_blocks: &[GapAckBlock]);
    fn on_timeout(&mut self);
}

impl Retransmission for Association {
    fn on_outgoing_data(&mut self, chunk_tsn: TSN) {
        // On fresh transmissions, perform RTT measurements.
        if chunk_tsn > self.rtx.tx_high_water_mark {
            // This is a newly sent chunk (not a retransmission), so take a measurement if needed.
            self.rtx.measurements.on_outgoing_chunk(chunk_tsn);
            // Raise the high water mark.
            self.rtx.tx_high_water_mark = chunk_tsn;
        }

        // R1) On any transmission, start the rtx timer if it is not already running.
        if self.rtx.timer.is_none() {
            self.rtx.timer = Some(self.resources.timer.sleep(self.rtx.measurements.rto))
        }
    }

    fn on_cumulative_ack(
        &mut self,
        cumulative_tsn_ack: TSN,
        earliest_outstanding_tsn: Option<TSN>,
    ) {
        // Perform RTT measurements
        self.rtx.measurements.on_cumulative_ack(cumulative_tsn_ack);

        if self.data.sent_queue.is_empty() && self.rtx.timer.is_some() {
            // R2) If all outstanding data has been acknowledged, then cancel the timer.
            self.rtx.timer = None;
        } else if let Some(earliest_outstanding_tsn) = earliest_outstanding_tsn {
            // R3) If the earliest outstanding TSN is acknowledged, then restart the timer.
            if cumulative_tsn_ack >= earliest_outstanding_tsn {
                self.rtx.timer = Some(self.resources.timer.sleep(self.rtx.measurements.rto));
            }
        }
    }

    // TODO remove
    fn on_gap_ack_block(&mut self, start: TSN, end: TSN) {
        // Perform RTT measurements
        self.rtx.measurements.on_gap_ack_block(start, end);
    }

    fn on_gap_ack_blocks(&mut self, cumulative_tsn_ack: TSN, gap_ack_blocks: &[GapAckBlock]) {
        let mut tsn = cumulative_tsn_ack;
        for block in gap_ack_blocks {
            let ack_start = cumulative_tsn_ack + block.start as u32;
            let ack_end = cumulative_tsn_ack + block.end as u32;
            // Chunks in the TSN range [ack_start,ack_end] (inclusive) are assumed to
            // have been received.  However, the receiver has the option of discarding them and
            // having us retransmit them, so they must stay in the sent queue until acknowledged
            // via the cumulative TSN.

            // Perform RTT measurements, if needed
            self.rtx.measurements.on_gap_ack_block(ack_start, ack_end);

            // This should always be true if the peer is constructing SACKs properly.
            if ack_start > tsn + 1 {
                let gap_start = tsn + 1;
                let gap_end = ack_start - 1;

                // This could just be a for loop, whenever std::iter::Step becomes stable.
                let mut gap_tsn = gap_start;
                loop {
                    // TODO: Mark this gap chunk for retransmission.

                    gap_tsn += 1;
                    if gap_tsn > gap_end {
                        break;
                    }
                }
            }

            // TODO: Store received ranges, so we can know if the peer decides to drop them?
            // (So we can implement R4.)

            tsn = ack_end;
        }

        // R4) When a TSN previously acknowledged in a gap ack block is no longer acknowledged
        // (e.g. it was dropped by the peer), then start the timer.
        //
        // TODO
    }

    fn on_timeout(&mut self) {
        // E1) Update congestion control as needed.
        //     - adjust ssthresh according to Section 7.2.3
        //     - set cwnd to the MTU

        // TODO

        // E2) Double RTO up to RTO.Max to provide back-off.

        self.rtx.measurements.rto *= 2;
        let rto_max = Duration::from_millis(DEFAULT_SCTP_PARAMETERS.rto_max);
        self.rtx.measurements.rto = self.rtx.measurements.rto.min(rto_max);

        // E3) Retransmit as many of the earliest DATA chunks as will fit into a single packet
        // based on the MTU.

        retransmit_immediate(self);

        // Any remaining DATA chunks should be "marked for retransmission" and sent as soon
        // as cwnd allows.

        retransmit_all_except_first(self);
    }
}

/// Immediately retransmit the earliest unacknowledged sent chunk.  Ideally, we would see how many
/// of the earliest chunks could fit into a packet given the current MTU.
fn retransmit_immediate(association: &mut Association) {
    // Retrieve the first unacknowledged chunk.
    let rtx_chunk = association.data.sent_queue.front().map(|c| c.clone());
    if let Some(rtx_chunk) = rtx_chunk {
        // Re-transmit chunk
        println!("re-sending chunk: {:?}", rtx_chunk);
        association.send_chunk(Chunk::Data(rtx_chunk));

        // E4) Restart timer
        association.rtx.timer = Some(
            association
                .resources
                .timer
                .sleep(association.rtx.measurements.rto),
        )
    }
}

/// "Mark" a range of unacknowledged packets for retransmission.
fn retransmit_range(association: &mut Association, first: TSN, last: TSN) {
    // TODO: Don't retransmit chunks that were acknowledged in the gap-ack blocks of the most
    // recent SACK.

    // Re-queue unacknowledged chunks in the specified range.
    let bytes =
        association
            .data
            .sent_queue
            .transfer_range(&mut association.data.send_queue, first, last);
    // Window accounting: Increase the peer receive window by however much we removed from the sent
    // queue.
    association.peer_rwnd += bytes as u32;
}

/// "Mark" all unacknowledged packets for retransmission.
#[allow(unused)]
fn retransmit_all(association: &mut Association) {
    // Re-queue unacknowledged chunks
    let bytes = association
        .data
        .sent_queue
        .transfer_all(&mut association.data.send_queue);
    // Window accounting: Increase the peer receive window by however much we removed from the sent
    // queue.
    association.peer_rwnd += bytes as u32;
}

/// "Mark" all unacknowledged packets for retransmission, except for the first.  (Which was
/// presumably sent via retransmit_immediate().)
fn retransmit_all_except_first(association: &mut Association) {
    if let Some(first) = association.data.sent_queue.front().map(|c| c.tsn) {
        if let Some(last) = association.data.sent_queue.back().map(|c| c.tsn) {
            if last > first {
                retransmit_range(association, first + 1, last);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct SmoothingState {
    srtt: Duration,   // Smoothed round-trip time
    rttvar: Duration, // Round-trip time variation
}

pub struct Measurements {
    rtt_measurement: Option<(TSN, Instant)>, // An in-progress RTT measurement.
    rtt_smoothing: Option<SmoothingState>,
    rto: Duration,
}

/// Clock granularity in nanoseconds.  Tokio-timer 0.1 has a granularity of 100ms, and tokio-timer
/// 0.2 has a granularity of 1ms.
/// TODO: Upgrade to tokio-timer 0.2!
const CLOCK_GRANULARITY_NS: u32 = 100_000_000; // 100ms

impl Measurements {
    pub fn new() -> Measurements {
        Measurements {
            rtt_measurement: None,
            rtt_smoothing: None,
            rto: Duration::from_millis(DEFAULT_SCTP_PARAMETERS.rto_initial),
        }
    }

    /// This should be called for each fresh outgoing chunk (not on retransmissions), so we can
    /// decide whether to start a new RTT measurement or not.
    pub fn on_outgoing_chunk(&mut self, chunk_tsn: TSN) {
        // Start a RTT measurement if one is not already in progress.
        if self.rtt_measurement.is_none() {
            self.rtt_measurement = Some((chunk_tsn, Instant::now()));
        }
    }

    /// This should be called for each received SACK, so the Measurements can conclude an RTT
    /// measurement, if needed.
    pub fn on_cumulative_ack(&mut self, cumulative_tsn_ack: TSN) {
        // If a RTT measurement is in-progress, see if it can be completed.
        if let Some((rtt_tsn, _)) = self.rtt_measurement {
            if rtt_tsn <= cumulative_tsn_ack {
                self.complete_rtt_measurement();
            }
        }
    }

    /// This should be called for each gap ack block in each received SACK, so the Measurements
    /// can conclude an RTT measurement, if needed.
    pub fn on_gap_ack_block(&mut self, start: TSN, end: TSN) {
        // If a RTT measurement is in-progress, see if it can be completed.
        if let Some((rtt_tsn, _)) = self.rtt_measurement {
            if rtt_tsn >= start && rtt_tsn <= end {
                self.complete_rtt_measurement();
            }
        }
    }

    /// Conclude the current RTT measurement and adjust SRTT (smoothed RTT), RTTVAR (RTT variance),
    /// and RTO (retransmission timeout) accordingly.
    fn complete_rtt_measurement(&mut self) {
        // We have received acknowledgement of the receipt of the measurement TSN, so calculate the
        // RTT and related variables.
        let (_, rtt_start) = self.rtt_measurement.take().unwrap(); // Caller verifies Some(_).
        let rtt = rtt_start.elapsed();

        let min = Duration::from_millis(DEFAULT_SCTP_PARAMETERS.rto_min);
        let max = Duration::from_millis(DEFAULT_SCTP_PARAMETERS.rto_max);

        match self.rtt_smoothing {
            Some(SmoothingState {
                mut srtt,
                mut rttvar,
            }) => {
                // Update the SRTT/RTTVAR according to RFC 4960 6.3.1 C3.

                #[inline]
                fn duration_difference(a: &Duration, b: &Duration) -> Duration {
                    if *a > *b {
                        *a - *b
                    } else {
                        *b - *a
                    }
                }
                let beta = DEFAULT_SCTP_PARAMETERS.rto_beta;
                let alpha = DEFAULT_SCTP_PARAMETERS.rto_alpha;

                // RTTVAR <- (1 - RTO.Beta) * RTTVAR + RTO.Beta * |SRTT - R'|
                rttvar = rttvar * (beta.1 - beta.0) / beta.1
                    + duration_difference(&srtt, &rtt) * beta.0 / beta.1;
                if rttvar == Duration::new(0, 0) {
                    // 6.3.1(G1): Adjust a zero RTTVAR to be the clock granularity.
                    rttvar = Duration::new(0, CLOCK_GRANULARITY_NS);
                }
                // SRTT <- (1 - RTO.Alpha) * SRTT + RTO.Alpha * R'
                srtt = srtt * (alpha.1 - alpha.0) / alpha.1 + rtt * alpha.0 / alpha.1;
                // RTO <- SRTT + 4 * RTTVAR
                self.rto = srtt + rttvar * 4;

                self.rtt_smoothing = Some(SmoothingState { srtt, rttvar });
            }
            None => {
                // No current SRTT/RTTVAR has yet been established, so initialize these according
                // to RFC 4960 6.3.1 C2.

                // SRTT <- R
                let srtt = rtt;
                // RTTVAR <- R/2
                let mut rttvar = rtt / 2;
                if rttvar == Duration::new(0, 0) {
                    // 6.3.1(G1): Adjust a zero RTTVAR to be the clock granularity.
                    rttvar = Duration::new(0, CLOCK_GRANULARITY_NS);
                }
                // RTO <- SRTT + 4 * RTTVAR
                self.rto = srtt + rttvar * 4;

                self.rtt_smoothing = Some(SmoothingState { srtt, rttvar });
            }
        }

        if self.rto < min {
            self.rto = min;
        } else if self.rto > max {
            self.rto = max;
        }

        fn duration_to_us(duration: Duration) -> u32 {
            duration.as_secs() as u32 * 1_000_000 + duration.subsec_nanos() / 1_000
        }
        trace!(
            "New RTT measurement: {:?} srtt={:?} rttvar={:?} rto={:?}",
            duration_to_us(rtt),
            duration_to_us(self.rtt_smoothing.unwrap().srtt),
            duration_to_us(self.rtt_smoothing.unwrap().rttvar),
            duration_to_us(self.rto),
        );

        // TODO: [6.3.1] C4-C7 ?
    }
}
