use crate::varint::VarintDecoder;
use bytes::{Buf, Bytes, IntoBuf};
use bytes_queue::BytesQueue;
use std::{borrow::Cow, io::Cursor, string::FromUtf8Error};

pub enum Never {}

pub struct ParamWrapper<'a> {
    key_len: usize,
    value_len: usize,
    buf: &'a mut BytesQueue<Cursor<Bytes>>,
}

impl<'a> ParamWrapper<'a> {
    fn parse_buf_into<F, R>(buf: &mut impl Buf, f: F) -> R
    where
        F: Fn(&mut dyn Buf) -> R,
    {
        let res = f(buf);
        let rem = buf.remaining();
        if 0 < rem {
            buf.advance(rem);
        }
        res
    }

    pub fn parse_bufs_into<FK, FV, RK, RV>(self, f_key: FK, f_value: FV) -> (RK, RV)
    where
        FK: Fn(&mut dyn Buf) -> RK,
        FV: Fn(&mut dyn Buf) -> RV,
    {
        let key = Self::parse_buf_into(&mut self.buf.by_ref().take(self.key_len), f_key);
        let value = Self::parse_buf_into(&mut self.buf.by_ref().take(self.value_len), f_value);
        (key, value)
    }

    fn parse_byte_cow_into<F, R>(buf: &mut impl Buf, f: F) -> R
    where
        F: Fn(Cow<'_, [u8]>) -> R,
    {
        let rem = buf.remaining();
        let b = buf.bytes();
        if b.len() == rem {
            // buf is already a contiguous slice of memory, we can pass it along
            let ret = f(Cow::Borrowed(b));
            buf.advance(rem);
            ret
        } else {
            let b: Vec<u8> = buf.collect();
            f(Cow::Owned(b))
        }
    }

    pub fn parse_byte_cows_into<FK, FV, RK, RV>(self, f_key: FK, f_value: FV) -> (RK, RV)
    where
        FK: Fn(Cow<'_, [u8]>) -> RK,
        FV: Fn(Cow<'_, [u8]>) -> RV,
    {
        let key = Self::parse_byte_cow_into(&mut self.buf.by_ref().take(self.key_len), f_key);
        let value = Self::parse_byte_cow_into(&mut self.buf.by_ref().take(self.value_len), f_value);
        (key, value)
    }

    pub fn into_vecs(self) -> (Vec<u8>, Vec<u8>) {
        let key = self.buf.by_ref().take(self.key_len).collect();
        let value = self.buf.by_ref().take(self.value_len).collect();
        (key, value)
    }

    pub fn into_utf8_strings(self) -> Result<(String, String), FromUtf8Error> {
        let (key, value) = self.into_vecs();
        let key = String::from_utf8(key)?;
        let value = String::from_utf8(value)?;
        Ok((key, value))
    }
}

pub trait ParamHandler {
    type Err;

    fn handle_param(&mut self, param: ParamWrapper<'_>) -> Result<(), Self::Err>;
}

impl ParamHandler for Vec<(String, String)> {
    type Err = FromUtf8Error;

    fn handle_param(&mut self, param: ParamWrapper<'_>) -> Result<(), FromUtf8Error> {
        self.push(param.into_utf8_strings()?);
        Ok(())
    }
}

impl ParamHandler for Vec<(Vec<u8>, Vec<u8>)> {
    type Err = Never;

    fn handle_param(&mut self, param: ParamWrapper<'_>) -> Result<(), Never> {
        self.push(param.into_vecs());
        Ok(())
    }
}

pub struct ParamsDecoder<PH> {
    varint_decoder: VarintDecoder,
    buf: BytesQueue<Cursor<Bytes>>,
    curr_key_len: Option<usize>,
    curr_value_len: Option<usize>,
    handler: Option<PH>,
}

impl<PH> ParamsDecoder<PH>
where
    PH: ParamHandler + Default,
{
    pub fn new() -> ParamsDecoder<PH> {
        ParamsDecoder {
            varint_decoder: VarintDecoder::new(),
            buf: BytesQueue::new(),
            curr_key_len: None,
            curr_value_len: None,
            handler: Some(PH::default()),
        }
    }
}

impl<PH> ParamsDecoder<PH>
where
    PH: ParamHandler,
{
    pub fn with_handler(handler: PH) -> ParamsDecoder<PH> {
        ParamsDecoder {
            varint_decoder: VarintDecoder::new(),
            buf: BytesQueue::new(),
            curr_key_len: None,
            curr_value_len: None,
            handler: Some(handler),
        }
    }

    pub fn decode(&mut self, buf: Bytes) -> Option<Result<PH, PH::Err>> {
        assert!(self.handler.is_some());

        if buf.len() == 0 {
            // end of stream

            assert!(!self.buf.has_remaining());
            assert_eq!(self.curr_key_len, None);
            assert_eq!(self.curr_value_len, None);

            return Ok(self.handler.take()).transpose();
        }

        self.buf.push(buf.into_buf());

        loop {
            let curr_key_len = self.curr_key_len.or_else(|| {
                let len = self.varint_decoder.decode(&mut self.buf)?;
                self.curr_key_len = Some(len as usize);
                self.curr_key_len
            })?;

            let curr_value_len = self.curr_value_len.or_else(|| {
                let len = self.varint_decoder.decode(&mut self.buf)?;
                self.curr_value_len = Some(len as usize);
                self.curr_value_len
            })?;

            let rem = self.buf.remaining();
            let len = curr_key_len + curr_value_len;
            if rem < len {
                return None;
            }

            let target_rem = rem - len;

            let handle_res = self.handler.as_mut().unwrap().handle_param(ParamWrapper {
                key_len: curr_key_len,
                value_len: curr_value_len,
                buf: &mut self.buf,
            });

            let advance = self.buf.remaining() - target_rem;

            if 0 < advance {
                self.buf.advance(advance);
            }

            self.curr_key_len = None;
            self.curr_value_len = None;

            if let Err(err) = handle_res {
                return Some(Err(err));
            }
        }
    }
}

impl<PH> Default for ParamsDecoder<PH>
where
    PH: ParamHandler + Default,
{
    fn default() -> ParamsDecoder<PH> {
        ParamsDecoder::new()
    }
}
