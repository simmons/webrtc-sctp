//
// bin2rust - render the binary input as a byte slice constant suitable
// for inclusion in Rust source.
//

use std::io::{self, Read};

const INDENT: &str = "    ";
const COLUMNS: usize = 8;

fn render_ascii(bytes: &[u8]) -> String {
    let mut ascii = String::with_capacity(COLUMNS);
    for &byte in bytes {
        let ascii_char = match byte {
            c @ 0x20 ... 0x7E => { c as char },
            _ => { '.' }
        };
        ascii.push(ascii_char);
    }
    String::from(ascii.trim_right())
}

fn print_row(offset: usize, bytes: &[u8]) {
    const BYTE_WIDTH: usize = 6;
    print!("{}", INDENT);
    let mut first = true;

    // Print hex bytes
    for byte in bytes {
        if first {
            first = false;
        } else {
            print!(", ");
        }
        print!("0x{:02x}", byte);
    }
    print!(",");
    // Add trailing spacing, if needed
    for _ in 0..(COLUMNS-bytes.len()) {
        for _ in 0..BYTE_WIDTH {
            print!(" ");
        }
    }
    // Print offset and ASCII representation
    print!(" // {:04x}: ", offset);
    println!("{}", render_ascii(bytes));
}

fn main() {
    println!("const BYTES: &[u8] = &[");
    let mut offset = 0usize;
    let mut row = Vec::<u8>::with_capacity(COLUMNS);

    for byte in io::stdin().bytes() {
        let byte = byte.unwrap();
        row.push(byte);
        if row.len() == COLUMNS {
            print_row(offset, &row);
            row.clear();
            offset += COLUMNS;
        }
    }
    if ! row.is_empty() {
            print_row(offset, &row);
            row.clear();
    }

    println!("];");
}
