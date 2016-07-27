//! Provide traits and structs to abstract RFC 1982 serial number arithmetic.  This is use, for
//! example, to compare transmission sequence numbers (TSNs).

use std::cmp::Ordering;
use std::fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex};
use std::hash::{Hash, Hasher};
use std::ops::{Add, AddAssign, Sub, SubAssign};

pub trait SerialNumber:
    Copy
    + Debug
    + Display
    + Hash
    + LowerHex
    + UpperHex
    + Ord
    + PartialOrd
    + Add<Output = Self>
    + Sub<Output = Self>
    + AddAssign
    + SubAssign
{
    const THRESHOLD: Self;
    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;
    fn next(self) -> Self;
    fn previous(self) -> Self;
}

impl SerialNumber for u32 {
    const THRESHOLD: u32 = 0x8000_0000;
    fn wrapping_add(self, rhs: Self) -> Self {
        u32::wrapping_add(self, rhs)
    }
    fn wrapping_sub(self, rhs: Self) -> Self {
        u32::wrapping_sub(self, rhs)
    }
    fn next(self) -> Self {
        u32::wrapping_add(self, 1u32)
    }
    fn previous(self) -> Self {
        u32::wrapping_sub(self, 1u32)
    }
}

impl SerialNumber for u16 {
    const THRESHOLD: u16 = 0x8000;
    fn wrapping_add(self, rhs: Self) -> Self {
        u16::wrapping_add(self, rhs)
    }
    fn wrapping_sub(self, rhs: Self) -> Self {
        u16::wrapping_sub(self, rhs)
    }
    fn next(self) -> Self {
        u16::wrapping_add(self, 1u16)
    }
    fn previous(self) -> Self {
        u16::wrapping_sub(self, 1u16)
    }
}

/// Implement RFC 1982 "Serial Number Arithmetic"
#[derive(Clone, Copy)]
pub struct Serial<T: SerialNumber>(pub T);

impl<T: SerialNumber> Serial<T> {
    pub fn new(n: T) -> Self {
        Serial(n)
    }
    pub fn incr(&mut self) {
        *self = Serial(self.0.next());
    }
    pub fn decr(&mut self) {
        *self = Serial(self.0.previous());
    }
    pub fn next(&self) -> Serial<T> {
        Serial(self.0.next())
    }
    pub fn previous(&self) -> Serial<T> {
        Serial(self.0.previous())
    }
}

impl From<u32> for Serial<u32> {
    fn from(n: u32) -> Serial<u32> {
        Serial(n)
    }
}

impl From<Serial<u32>> for u32 {
    fn from(s: Serial<u32>) -> u32 {
        s.0
    }
}

impl From<u16> for Serial<u16> {
    fn from(n: u16) -> Serial<u16> {
        Serial(n)
    }
}

impl From<Serial<u16>> for u16 {
    fn from(s: Serial<u16>) -> u16 {
        s.0
    }
}

impl<T: SerialNumber> Ord for Serial<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.0 == other.0 {
            Ordering::Equal
        } else if self.0 < other.0 {
            if other.0 - self.0 <= T::THRESHOLD {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        } else {
            if self.0 - other.0 > T::THRESHOLD {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
    }
}

impl<T: SerialNumber> PartialOrd for Serial<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: SerialNumber> PartialEq for Serial<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: SerialNumber> Eq for Serial<T> {}

impl<T: SerialNumber> Hash for Serial<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<T: SerialNumber> Add for Serial<T> {
    type Output = Serial<T>;

    fn add(self, other: Serial<T>) -> Serial<T> {
        Serial(self.0.wrapping_add(other.0))
    }
}

impl<T: SerialNumber> Add<T> for Serial<T> {
    type Output = Serial<T>;

    fn add(self, other: T) -> Serial<T> {
        Serial(self.0.wrapping_add(other))
    }
}

impl<T: SerialNumber> Sub for Serial<T> {
    type Output = Serial<T>;

    fn sub(self, other: Serial<T>) -> Serial<T> {
        Serial(self.0.wrapping_sub(other.0))
    }
}

impl<T: SerialNumber> Sub<T> for Serial<T> {
    type Output = Serial<T>;

    fn sub(self, other: T) -> Serial<T> {
        Serial(self.0.wrapping_sub(other))
    }
}

impl<T: SerialNumber> AddAssign<T> for Serial<T> {
    fn add_assign(&mut self, other: T) {
        *self = Serial(self.0.wrapping_add(other))
    }
}

impl<T: SerialNumber> SubAssign<T> for Serial<T> {
    fn sub_assign(&mut self, other: T) {
        *self = Serial(self.0.wrapping_sub(other))
    }
}

impl<T: SerialNumber> Display for Serial<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<T: SerialNumber> Debug for Serial<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<T: SerialNumber> LowerHex for Serial<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl<T: SerialNumber> UpperHex for Serial<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        UpperHex::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPARISON_PAIRS: &[(u32, u32, Ordering)] = &[
        // equal
        (0x0000_0000, 0x0000_0000, Ordering::Equal),
        (0x0000_0001, 0x0000_0001, Ordering::Equal),
        (0x7FFF_FFFF, 0x7FFF_FFFF, Ordering::Equal),
        (0x8000_0000, 0x8000_0000, Ordering::Equal),
        (0x8000_0001, 0x8000_0001, Ordering::Equal),
        (0xFFFF_FFFE, 0xFFFF_FFFE, Ordering::Equal),
        (0xFFFF_FFFF, 0xFFFF_FFFF, Ordering::Equal),
        // less than
        (0x0000_0000, 0x0000_0001, Ordering::Less),
        (0x0000_0001, 0x0000_0002, Ordering::Less),
        (0x0000_0002, 0x0000_0003, Ordering::Less),
        (0x0000_0003, 0x0000_0004, Ordering::Less),
        (0xFFFF_FFFB, 0xFFFF_FFFC, Ordering::Less),
        (0xFFFF_FFFC, 0xFFFF_FFFD, Ordering::Less),
        (0xFFFF_FFFD, 0xFFFF_FFFE, Ordering::Less),
        (0xFFFF_FFFE, 0xFFFF_FFFF, Ordering::Less),
        (0x0000_0000, 0x7FFF_FFFF, Ordering::Less),
        (0x0000_0001, 0x8000_0000, Ordering::Less),
        (0x0000_0002, 0x8000_0001, Ordering::Less),
        (0x0000_0003, 0x8000_0002, Ordering::Less),
        // greater than
        (0x0000_0001, 0x0000_0000, Ordering::Greater),
        (0x0000_0002, 0x0000_0001, Ordering::Greater),
        (0x0000_0003, 0x0000_0002, Ordering::Greater),
        (0x0000_0004, 0x0000_0003, Ordering::Greater),
        (0xFFFF_FFFC, 0xFFFF_FFFB, Ordering::Greater),
        (0xFFFF_FFFD, 0xFFFF_FFFC, Ordering::Greater),
        (0xFFFF_FFFE, 0xFFFF_FFFD, Ordering::Greater),
        (0xFFFF_FFFF, 0xFFFF_FFFE, Ordering::Greater),
        (0x7FFF_FFFF, 0x0000_0000, Ordering::Greater),
        (0x8000_0000, 0x0000_0001, Ordering::Greater),
        (0x8000_0001, 0x0000_0002, Ordering::Greater),
        (0x8000_0002, 0x0000_0003, Ordering::Greater),
        // less than (via modulus)
        (0xFFFF_FFFF, 0x0000_0000, Ordering::Less),
        (0xFFFF_FFFE, 0x0000_0001, Ordering::Less),
        (0xFFFF_FFFD, 0x0000_0002, Ordering::Less),
        (0xFFFF_FFFC, 0x0000_0003, Ordering::Less),
        (0x8000_0001, 0x0000_0000, Ordering::Less),
        (0x8000_0002, 0x0000_0001, Ordering::Less),
        (0x8000_0003, 0x0000_0002, Ordering::Less),
        (0x8000_0004, 0x0000_0003, Ordering::Less),
        // greater than (via modulus)
        (0x0000_0000, 0xFFFF_FFFF, Ordering::Greater),
        (0x0000_0001, 0xFFFF_FFFE, Ordering::Greater),
        (0x0000_0002, 0xFFFF_FFFD, Ordering::Greater),
        (0x0000_0003, 0xFFFF_FFFC, Ordering::Greater),
        (0x0000_0000, 0x8000_0001, Ordering::Greater),
        (0x0000_0001, 0x8000_0002, Ordering::Greater),
        (0x0000_0002, 0x8000_0003, Ordering::Greater),
        (0x0000_0003, 0x8000_0004, Ordering::Greater),
        // Undefined comparisons
        // NOTE: For simplicity, we return either Less or Greater for
        // undefined comparisons, to provide the illusion of a total
        // ordering.  This is allowed in RFC 1982:
        //     "Thus the problem case is left undefined, implementations
        //     are free to return either result, or to flag an error,
        //     and users must take care not to depend on any particular
        //     outcome."
        (0xFFFF_FFFE, 0x7FFF_FFFE, Ordering::Greater),
        (0xFFFF_FFFF, 0x7FFF_FFFF, Ordering::Greater),
        (0x0000_0000, 0x8000_0000, Ordering::Less),
        (0x0000_0001, 0x8000_0001, Ordering::Less),
        (0x0000_0002, 0x8000_0002, Ordering::Less),
        (0x7FFF_FFFE, 0xFFFF_FFFE, Ordering::Less),
        (0x7FFF_FFFF, 0xFFFF_FFFF, Ordering::Less),
        (0x8000_0000, 0x0000_0000, Ordering::Greater),
        (0x8000_0001, 0x0000_0001, Ordering::Greater),
        (0x8000_0002, 0x0000_0002, Ordering::Greater),
    ];

    /// Collapse a u32 into a u16 by removing the middle 16 bits.  This produces
    /// useful u16 test cases from the existing u32 test cases.
    fn collapse(n: u32) -> u16 {
        ((n >> 16 & 0xFF00) | (n & 0xFF)) as u16
    }

    #[test]
    fn test_serial_compare() {
        for &(a, b, expected) in COMPARISON_PAIRS {
            // u32
            let s1 = Serial(a);
            let s2 = Serial(b);
            assert!(s1.cmp(&s2) == expected);

            // u16
            let s1 = Serial(collapse(a));
            let s2 = Serial(collapse(b));
            assert!(s1.cmp(&s2) == expected);
        }
    }

    const ADD_PAIRS: &[(u32, u32, u32)] = &[
        // small adds
        (0xFFFF_FFFE, 0x0000_0000, 0xFFFF_FFFE),
        (0xFFFF_FFFE, 0x0000_0001, 0xFFFF_FFFF),
        (0xFFFF_FFFE, 0x0000_0002, 0x0000_0000),
        (0xFFFF_FFFF, 0x0000_0000, 0xFFFF_FFFF),
        (0xFFFF_FFFF, 0x0000_0001, 0x0000_0000),
        (0xFFFF_FFFF, 0x0000_0002, 0x0000_0001),
        (0x0000_0000, 0x0000_0000, 0x0000_0000),
        (0x0000_0000, 0x0000_0001, 0x0000_0001),
        (0x0000_0000, 0x0000_0002, 0x0000_0002),
        (0x0000_0001, 0x0000_0000, 0x0000_0001),
        (0x0000_0001, 0x0000_0001, 0x0000_0002),
        (0x0000_0001, 0x0000_0002, 0x0000_0003),
        // large adds
        (0xFFFF_FFFF, 0x7FFF_FFFF, 0x7FFF_FFFE),
        (0xFFFF_FFFF, 0x8000_0000, 0x7FFF_FFFF),
        (0xFFFF_FFFF, 0x8000_0001, 0x8000_0000),
        (0x0000_0000, 0x7FFF_FFFF, 0x7FFF_FFFF),
        (0x0000_0000, 0x8000_0000, 0x8000_0000),
        (0x0000_0000, 0x8000_0001, 0x8000_0001),
        (0x0000_0001, 0x7FFF_FFFF, 0x8000_0000),
        (0x0000_0001, 0x8000_0000, 0x8000_0001),
        (0x0000_0001, 0x8000_0001, 0x8000_0002),
    ];

    #[test]
    fn test_serial_add() {
        for &(a, b, expected) in ADD_PAIRS {
            let s1 = Serial(a);
            let s2 = Serial(b);
            assert!(s1.add(s2) == Serial(expected));
            assert!(s2.add(s1) == Serial(expected));
        }
    }

    #[test]
    fn test_ops() {
        assert!(Serial(1u32) + Serial(2) == Serial(3));
        assert!(Serial(3u32) - Serial(2) == Serial(1));
        assert!(Serial(1u32) + 2 == Serial(3));
        assert!(Serial(3u32) - 2 == Serial(1));

        assert!(Serial(0xFFFF_FFFFu32) + Serial(1) == Serial(0));
        assert!(Serial(0xFFFF_FFFFu32) + 1 == Serial(0));
        assert!(Serial(0xFFFF_FFFFu32) + Serial(2) == Serial(1));
        assert!(Serial(0xFFFF_FFFFu32) + 2 == Serial(1));
        assert!(Serial(0x0000_0000u32) - Serial(1) == Serial(0xFFFF_FFFF));
        assert!(Serial(0x0000_0000u32) - 1 == Serial(0xFFFF_FFFF));
        assert!(Serial(0x0000_0001u32) - Serial(2) == Serial(0xFFFF_FFFF));
        assert!(Serial(0x0000_0001u32) - 2 == Serial(0xFFFF_FFFF));

        let mut s = Serial(0xFFFF_FFFFu32);
        assert_eq!(s, Serial(0xFFFF_FFFF));
        s += 1;
        assert_eq!(s, Serial(0x0000_0000));
        s += 1;
        assert_eq!(s, Serial(0x0000_0001));
        s -= 1;
        assert_eq!(s, Serial(0x0000_0000));
        s -= 1;
        assert_eq!(s, Serial(0xFFFF_FFFF));
    }
}
