#[allow(dead_code)]
pub struct SctpProtocolParameters {
    pub rto_initial: u64,
    pub rto_min: u64,
    pub rto_max: u64,
    pub max_burst: usize,
    pub rto_alpha: (u32, u32),
    pub rto_beta: (u32, u32),
    pub valid_cookie_life: u64,
    pub association_max_retrans: usize,
    pub path_max_retrans: usize,
    pub max_init_retransmits: usize,
    pub hb_interval: u64,
    pub hb_max_burst: usize,
    //
    pub secret_key_regeneration_interval: u64,
    // We don't allow the send queue to be larger than this, even if the peer advertises a larger
    // receive window.
    pub max_send_queue: usize,
}

pub const DEFAULT_SCTP_PARAMETERS: SctpProtocolParameters = SctpProtocolParameters {
    // RFC 4960 section 15, "Suggested SCTP Protocol Parameter Values"
    rto_initial: 3000, // milliseconds
    rto_min: 1000,     // milliseconds
    rto_max: 60000,    // milliseconds
    max_burst: 4,
    rto_alpha: (1, 8),           // numerator/denominator fraction tuples
    rto_beta: (1, 4),            // numerator/denominator fraction tuples
    valid_cookie_life: 60000,    // milliseconds
    association_max_retrans: 10, // attempts
    path_max_retrans: 5,         // attempts per destination address
    max_init_retransmits: 8,     // attempts
    hb_interval: 30000,          // milliseconds
    hb_max_burst: 1,
    //
    secret_key_regeneration_interval: 900000, // milliseconds (15 minutes)
    max_send_queue: 256 * 1024,               // 256K
};
