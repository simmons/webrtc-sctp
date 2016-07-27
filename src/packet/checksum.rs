//! Functions related to SCTP checksums

use crc::crc32;

const CHECKSUM_START_OFFSET: usize = 8;
const CHECKSUM_END_OFFSET: usize = 12;
const ZERO_CHECKSUM: &[u8] = &[0u8, 0, 0, 0];

fn read(packet: &[u8]) -> u32 {
    // NOTE: Is the SCTP checksum really supposed to be little endian?
    // Or is this an artifact of how the crc crate delivers the result?
    // TODO: Verify on a big-endian system.

    // Read checksum as little endian
    (packet[CHECKSUM_START_OFFSET + 3] as u32) << 24
        | (packet[CHECKSUM_START_OFFSET + 2] as u32) << 16
        | (packet[CHECKSUM_START_OFFSET + 1] as u32) << 8
        | (packet[CHECKSUM_START_OFFSET + 0] as u32)
}

fn compute(packet: &[u8]) -> u32 {
    // Calculate a checksum as if the checksum field was zeroed.
    let checksum: u32 = crc32::update(
        0,
        &crc32::CASTAGNOLI_TABLE,
        &packet[0..CHECKSUM_START_OFFSET],
    );
    let checksum: u32 = crc32::update(checksum, &crc32::CASTAGNOLI_TABLE, ZERO_CHECKSUM);
    crc32::update(
        checksum,
        &crc32::CASTAGNOLI_TABLE,
        &packet[CHECKSUM_END_OFFSET..],
    )
}

pub fn verify(packet: &[u8]) -> bool {
    if packet.len() < 12 {
        panic!("packet too small");
    }
    read(packet) == compute(packet)
}

/// Assume the packet checksum field is currently zeroed.
pub fn write(packet: &mut [u8]) {
    if packet.len() < 12 {
        panic!("packet too small");
    }

    let checksum = compute(packet);

    // Write the checksum field as little endian
    packet[CHECKSUM_START_OFFSET + 0] = (checksum & 0xFF) as u8;
    packet[CHECKSUM_START_OFFSET + 1] = (checksum >> 8 & 0xFF) as u8;
    packet[CHECKSUM_START_OFFSET + 2] = (checksum >> 16 & 0xFF) as u8;
    packet[CHECKSUM_START_OFFSET + 3] = (checksum >> 24 & 0xFF) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    // COOKIE ECHO + DATA
    const PACKET1: &[u8] = &[
        0x07, 0xe4, 0x07, 0xe4, 0xe6, 0x45, 0x90, 0x05, // 0000: .....E..
        0xfb, 0x2e, 0xd3, 0x1a, 0x0a, 0x00, 0x00, 0xe8, // 0008: ........
        0xf0, 0x5f, 0x15, 0x04, 0x5f, 0x05, 0xd8, 0x51, // 0010: ._.._..Q
        0xaa, 0xf3, 0x14, 0x2c, 0x37, 0xee, 0xab, 0xe8, // 0018: ...,7...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0020: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0028: ........
        0x00, 0x00, 0x00, 0x00, 0x05, 0x90, 0x45, 0xe6, // 0030: ......E.
        0x99, 0x88, 0xc9, 0xd9, 0x00, 0x00, 0x00, 0x00, // 0038: ........
        0x00, 0x00, 0x00, 0x00, 0x99, 0xe6, 0x01, 0x7a, // 0040: .......z
        0x04, 0x9f, 0xe1, 0x14, 0x0a, 0x00, 0x0a, 0x00, // 0048: ........
        0x53, 0x67, 0x54, 0xa2, 0x02, 0x00, 0x07, 0xe4, // 0050: SgT.....
        0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 0058: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0060: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0068: ........
        0xe4, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 0070: ........
        0x80, 0x02, 0x00, 0x24, 0x8d, 0x68, 0x80, 0xfc, // 0078: ...$.h..
        0xe1, 0x25, 0xf2, 0x6f, 0x5d, 0xf0, 0x3a, 0x14, // 0080: .%.o].:.
        0xa0, 0x06, 0x16, 0xa3, 0x91, 0x23, 0xce, 0x98, // 0088: .....#..
        0x84, 0xb6, 0xb0, 0x7b, 0x1f, 0x9c, 0x28, 0xeb, // 0090: ...{..(.
        0xb0, 0xee, 0x23, 0x50, 0x00, 0x00, 0x00, 0x00, // 0098: ..#P....
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00a0: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00a8: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00b0: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00b8: ........
        0x01, 0x00, 0x00, 0x24, 0xd9, 0xc9, 0x88, 0x99, // 00c0: ...$....
        0x00, 0x01, 0xa0, 0x00, 0x00, 0x0a, 0xff, 0xff, // 00c8: ........
        0x17, 0xeb, 0xe3, 0x26, 0x00, 0x0c, 0x00, 0x06, // 00d0: ...&....
        0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04, // 00d8: ........
        0xc0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // 00e0: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00e8: ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x21, // 00f0: .......!
        0x17, 0xeb, 0xe3, 0x26, 0x00, 0x00, 0x00, 0x00, // 00f8: ...&....
        0x00, 0x00, 0x00, 0x00, 0x79, 0x6f, 0x75, 0x20, // 0100: ....you
        0x73, 0x61, 0x79, 0x20, 0x67, 0x6f, 0x6f, 0x64, // 0108: say good
        0x62, 0x79, 0x65, 0x0a, 0x00, 0x00, 0x00, 0x00, // 0110: bye.....
    ];
    const PACKET1_EXPECTED_CHECKSUM: u32 = 0x1ad32efb;

    // DATA
    const PACKET2: &[u8] = &[
        0x07, 0xe4, 0x07, 0xe4, 0xe6, 0x45, 0x90, 0x05, // 0000: .....E..
        0xfd, 0xdc, 0x05, 0x63, 0x00, 0x03, 0x00, 0x1d, // 0008: ...c....
        0x17, 0xeb, 0xe3, 0x27, 0x00, 0x00, 0x00, 0x01, // 0010: ...'....
        0x00, 0x00, 0x00, 0x00, 0x69, 0x20, 0x73, 0x61, // 0018: ....i sa
        0x79, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a, // 0020: y hello.
        0x00, 0x00, 0x00, 0x00, // 0028: ....
    ];
    const PACKET2_EXPECTED_CHECKSUM: u32 = 0x6305dcfd;

    // SHUTDOWN
    const PACKET3: &[u8] = &[
        0x07, 0xe4, 0x07, 0xe4, 0xe6, 0x45, 0x90, 0x05, // 0000: .....E..
        0x89, 0xbf, 0x66, 0x6a, 0x07, 0x00, 0x00, 0x08, // 0008: ..fj....
        0xa2, 0x54, 0x67, 0x52, // 0010: .TgR
    ];
    const PACKET3_EXPECTED_CHECKSUM: u32 = 0x6a66bf89;

    fn clear_checksum(packet: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::from(packet);
        for offset in CHECKSUM_START_OFFSET..CHECKSUM_END_OFFSET {
            buffer[offset] = 0x00;
        }
        buffer
    }

    fn fill_checksum(packet: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::from(packet);
        for offset in CHECKSUM_START_OFFSET..CHECKSUM_END_OFFSET {
            buffer[offset] = 0xff;
        }
        buffer
    }

    #[test]
    fn test_checksum_read() {
        assert_eq!(read(PACKET1), PACKET1_EXPECTED_CHECKSUM);
        assert_eq!(read(PACKET2), PACKET2_EXPECTED_CHECKSUM);
        assert_eq!(read(PACKET3), PACKET3_EXPECTED_CHECKSUM);
        assert_eq!(read(&clear_checksum(PACKET1)), 0x00000000);
        assert_eq!(read(&clear_checksum(PACKET2)), 0x00000000);
        assert_eq!(read(&clear_checksum(PACKET3)), 0x00000000);
        assert_eq!(read(&fill_checksum(PACKET1)), 0xffffffff);
        assert_eq!(read(&fill_checksum(PACKET2)), 0xffffffff);
        assert_eq!(read(&fill_checksum(PACKET3)), 0xffffffff);
    }

    #[test]
    fn test_checksum_compute() {
        assert_eq!(compute(PACKET1), PACKET1_EXPECTED_CHECKSUM);
        assert_eq!(compute(PACKET2), PACKET2_EXPECTED_CHECKSUM);
        assert_eq!(compute(PACKET3), PACKET3_EXPECTED_CHECKSUM);
        assert_eq!(compute(&clear_checksum(PACKET1)), PACKET1_EXPECTED_CHECKSUM);
        assert_eq!(compute(&clear_checksum(PACKET2)), PACKET2_EXPECTED_CHECKSUM);
        assert_eq!(compute(&clear_checksum(PACKET3)), PACKET3_EXPECTED_CHECKSUM);
        assert_eq!(compute(&fill_checksum(PACKET1)), PACKET1_EXPECTED_CHECKSUM);
        assert_eq!(compute(&fill_checksum(PACKET2)), PACKET2_EXPECTED_CHECKSUM);
        assert_eq!(compute(&fill_checksum(PACKET3)), PACKET3_EXPECTED_CHECKSUM);
    }

    #[test]
    fn test_checksum_verify() {
        assert!(verify(PACKET1));
        assert!(verify(PACKET2));
        assert!(verify(PACKET3));
        assert!(!verify(&clear_checksum(PACKET1)));
        assert!(!verify(&clear_checksum(PACKET2)));
        assert!(!verify(&clear_checksum(PACKET3)));
        assert!(!verify(&fill_checksum(PACKET1)));
        assert!(!verify(&fill_checksum(PACKET2)));
        assert!(!verify(&fill_checksum(PACKET3)));
    }

    #[test]
    fn test_checksum_write() {
        let mut packet1 = clear_checksum(PACKET1).to_owned();
        let mut packet2 = clear_checksum(PACKET1).to_owned();
        let mut packet3 = clear_checksum(PACKET1).to_owned();
        write(&mut packet1);
        write(&mut packet2);
        write(&mut packet3);
        assert!(verify(&packet1));
        assert!(verify(&packet2));
        assert!(verify(&packet3));

        let mut packet1 = fill_checksum(PACKET1).to_owned();
        let mut packet2 = fill_checksum(PACKET1).to_owned();
        let mut packet3 = fill_checksum(PACKET1).to_owned();
        write(&mut packet1);
        write(&mut packet2);
        write(&mut packet3);
        assert!(verify(&packet1));
        assert!(verify(&packet2));
        assert!(verify(&packet3));
    }
}
