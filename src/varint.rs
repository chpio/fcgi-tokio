use std::num::NonZeroU8;

use bytes::{Buf, BufMut, BytesMut};

const MULTIBYTE_FLAG: u8 = 0b1000_0000;
const MULTIBYTE_MASK: u8 = 0b0111_1111;

pub struct VarintDecoder {
    first: Option<NonZeroU8>,
}

impl VarintDecoder {
    pub fn new() -> VarintDecoder {
        VarintDecoder { first: None }
    }

    pub fn decode(&mut self, buf: &mut impl Buf) -> Option<u32> {
        let first = match self.first {
            Some(first) => {
                if buf.remaining() < 3 {
                    return None;
                }

                self.first = None;

                first.get()
            }
            None => {
                if !buf.has_remaining() {
                    return None;
                }
                let first = buf.get_u8();
                if first & MULTIBYTE_FLAG != MULTIBYTE_FLAG {
                    return Some(first as u32);
                }

                if buf.remaining() < 3 {
                    // can't be zero because MULTIBYTE_FLAG bit is set
                    self.first = Some(NonZeroU8::new(first).unwrap());
                    return None;
                }

                first
            }
        };

        let mut rest = [0; 3];
        buf.copy_to_slice(&mut rest);
        let ret = (((first & MULTIBYTE_MASK) as u32) << 24)
            + ((rest[0] as u32) << 16)
            + ((rest[1] as u32) << 8)
            + (rest[2] as u32);
        Some(ret)
    }
}

pub fn put_varint(buf: &mut BytesMut, int: u32) {
    if int < MULTIBYTE_FLAG as u32 {
        buf.reserve(1);
        buf.put_u8(int as u8);
    } else {
        let mut bytes = int.to_be_bytes();
        assert!(
            bytes[0] & MULTIBYTE_FLAG != MULTIBYTE_FLAG,
            "varint overflow"
        );
        bytes[0] |= MULTIBYTE_FLAG;
        buf.reserve(4);
        buf.put_slice(&bytes);
    }
}
