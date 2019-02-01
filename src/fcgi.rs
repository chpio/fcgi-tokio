use bytes::{Buf, BufMut, BytesMut, IntoBuf};
use futures::{try_ready, Async, AsyncSink, Poll, Sink, StartSend, Stream};
use std::collections::VecDeque;
use tokio::io::{self, AsyncRead, AsyncWrite};

const HEADER_LEN: usize = 8;
const WRITE_SOFT_LIMIT: usize = 16 * 1024;

#[derive(Debug)]
pub enum Role {
    Responder,
    Authorizer,
    Filter,
}

impl Role {
    pub fn from_number(role_number: u16) -> Option<Role> {
        use Role::*;

        match role_number {
            1 => Some(Responder),
            2 => Some(Authorizer),
            3 => Some(Filter),
            _ => None,
        }
    }

    pub fn as_number(&self) -> u16 {
        use Role::*;

        match self {
            Responder => 1,
            Authorizer => 2,
            Filter => 3,
        }
    }
}

#[derive(Debug)]
pub enum ProtocolStatus {
    RequestComplete,
    CanNotMultiplexConnection,
    Overloaded,
    UnknownRole,
}

impl ProtocolStatus {
    pub fn from_number(role_number: u8) -> Option<ProtocolStatus> {
        use ProtocolStatus::*;

        match role_number {
            0 => Some(RequestComplete),
            1 => Some(CanNotMultiplexConnection),
            2 => Some(Overloaded),
            3 => Some(UnknownRole),
            _ => None,
        }
    }

    pub fn as_number(&self) -> u8 {
        use ProtocolStatus::*;

        match self {
            RequestComplete => 0,
            CanNotMultiplexConnection => 1,
            Overloaded => 2,
            UnknownRole => 3,
        }
    }
}

#[derive(Debug)]
pub enum Record {
    BeginRequest {
        request_id: u16,
        role: Role,
        flags: u8, // TODO
    },
    AbortRequest {
        request_id: u16,
    },
    EndRequest {
        request_id: u16,

        /// CGI exit code
        app_status: u32,
        protocol_status: ProtocolStatus,
    },
    Params {
        request_id: u16,
        body: BytesMut,
    },
    StdIn {
        request_id: u16,
        body: BytesMut,
    },
    StdOut {
        request_id: u16,
        body: BytesMut,
    },
    StdErr {
        request_id: u16,
        body: BytesMut,
    },
    Data {
        request_id: u16,
        body: BytesMut,
    },
    GetValues {
        body: BytesMut,
    },
    GetValuesResult {
        body: BytesMut,
    },
    UnknownType {
        type_number: u8,
    },
}

impl Record {
    pub fn as_type_number(&self) -> u8 {
        use Record::*;

        match self {
            BeginRequest { .. } => 1,
            AbortRequest { .. } => 2,
            EndRequest { .. } => 3,
            Params { .. } => 4,
            StdIn { .. } => 5,
            StdOut { .. } => 6,
            StdErr { .. } => 7,
            Data { .. } => 8,
            GetValues { .. } => 9,
            GetValuesResult { .. } => 10,
            UnknownType { .. } => 11,
        }
    }

    pub fn request_id(&self) -> u16 {
        use Record::*;

        match self {
            BeginRequest { request_id, .. } => *request_id,
            AbortRequest { request_id, .. } => *request_id,
            EndRequest { request_id, .. } => *request_id,
            Params { request_id, .. } => *request_id,
            StdIn { request_id, .. } => *request_id,
            StdOut { request_id, .. } => *request_id,
            StdErr { request_id, .. } => *request_id,
            Data { request_id, .. } => *request_id,
            GetValues { .. } => 0,
            GetValuesResult { .. } => 0,
            UnknownType { .. } => 0,
        }
    }
}

struct DecodeState {
    type_number: u8,
    request_id: u16,
    body_padding_len: usize,
    padding_len: u8,
}

pub struct FcgiDecoder<S> {
    socket: S,
    read_buf: BytesMut,
    decode_state: Option<DecodeState>,
}

impl<S> FcgiDecoder<S>
where
    S: AsyncRead,
{
    pub fn new(reader: S) -> FcgiDecoder<S> {
        FcgiDecoder {
            socket: reader,
            read_buf: BytesMut::new(),
            decode_state: None,
        }
    }

    /// `Ok(Async::Ready)` means the socket is closed
    fn fill_read_buf(&mut self) -> Result<Async<()>, io::Error> {
        loop {
            self.read_buf.reserve(1024);
            let n = try_ready!(self.socket.read_buf(&mut self.read_buf));
            if n == 0 {
                return Ok(Async::Ready(()));
            }
        }
    }

    fn decode_record(read_buf: &mut BytesMut, state: &DecodeState) -> Option<Record> {
        use Record::*;

        if read_buf.len() < state.body_padding_len {
            return None;
        }

        let buf = read_buf.split_to(state.body_padding_len - state.padding_len as usize);
        read_buf.advance(state.padding_len as usize);

        let request_id = state.request_id;

        let record = match state.type_number {
            1 => {
                let mut buf = buf.into_buf();
                let role = buf.get_u16_be();
                let flags = buf.get_u8();
                // buf.advance(5); // reserved

                BeginRequest {
                    request_id,
                    role: Role::from_number(role).expect("unknown role number"), // TODO
                    flags,
                }
            }
            2 => AbortRequest { request_id },
            3 => {
                let mut buf = buf.into_buf();
                let app_status = buf.get_u32_be();
                let protocol_status = buf.get_u8();
                // buf.advance(3); // reserved

                EndRequest {
                    request_id,
                    app_status,
                    protocol_status: ProtocolStatus::from_number(protocol_status)
                        .expect("unknown status number"), // TODO
                }
            }
            4 => {
                Params {
                    request_id,
                    body: buf,
                }
            }
            5 => {
                StdIn {
                    request_id,
                    body: buf,
                }
            }
            6 => {
                StdOut {
                    request_id,
                    body: buf,
                }
            }
            7 => {
                StdErr {
                    request_id,
                    body: buf,
                }
            }
            8 => {
                Data {
                    request_id,
                    body: buf,
                }
            }
            9 => {
                assert_eq!(
                    request_id, 0,
                    "request_id is not 0 for management FCGI record"
                );
                GetValues { body: buf }
            }
            10 => {
                assert_eq!(
                    request_id, 0,
                    "request_id is not 0 for management FCGI record"
                );
                GetValuesResult { body: buf }
            }
            type_number @ _ => UnknownType { type_number },
        };

        // assert!(buf.is_empty());

        Some(record)
    }
}

impl<S> Stream for FcgiDecoder<S>
where
    S: AsyncRead,
{
    type Item = Record;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let socket_closed = self.fill_read_buf()?.is_ready();

        match &self.decode_state {
            None => {
                if HEADER_LEN <= self.read_buf.len() {
                    let mut buf = self.read_buf.split_to(HEADER_LEN).into_buf();
                    let version = buf.get_u8();
                    let type_number = buf.get_u8();
                    let request_id = buf.get_u16_be();
                    let body_len = buf.get_u16_be();
                    let padding_len = buf.get_u8();
                    // let reserved = buf.get_u8();

                    assert_eq!(version, 1, "unexpected FCGI version");
                    // assert_eq!(reserved, 0, "unexpected FCGI reserved");

                    let state = DecodeState {
                        type_number,
                        request_id,
                        body_padding_len: body_len as usize + padding_len as usize,
                        padding_len,
                    };

                    if let Some(record) = Self::decode_record(&mut self.read_buf, &state) {
                        return Ok(Async::Ready(Some(record)));
                    } else {
                        self.read_buf.reserve(state.body_padding_len);
                        self.decode_state = Some(state);
                    }
                }
            }
            Some(state) => {
                if let Some(record) = Self::decode_record(&mut self.read_buf, state) {
                    self.decode_state = None;
                    return Ok(Async::Ready(Some(record)));
                }
            }
        }

        if socket_closed {
            Ok(Async::Ready(None))
        } else {
            Ok(Async::NotReady)
        }
    }
}

pub struct FcgiEncoder<S> {
    socket: S,
    queued_bytes: usize,
    write_queue: VecDeque<BytesMut>,
}

impl<S> FcgiEncoder<S>
where
    S: AsyncWrite,
{
    pub fn new(writer: S) -> FcgiEncoder<S> {
        FcgiEncoder {
            socket: writer,
            queued_bytes: 0,
            write_queue: VecDeque::new(),
        }
    }
}

impl<S> Sink for FcgiEncoder<S>
where
    S: AsyncWrite,
{
    type SinkItem = Record;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        use Record::*;

        if WRITE_SOFT_LIMIT <= self.queued_bytes
            && self.poll_complete()?.is_not_ready()
            && WRITE_SOFT_LIMIT <= self.queued_bytes
        {
            return Ok(AsyncSink::NotReady(item));
        }

        let request_id = item.request_id();
        let item_type_number = item.as_type_number();

        let body = match item {
            BeginRequest {
                request_id: _,
                role,
                flags,
            } => {
                let mut buf = BytesMut::with_capacity(8);
                buf.put_u16_be(role.as_number());
                buf.put_u8(flags);
                buf.put_slice(&[0u8; 5]);
                buf
            }
            AbortRequest { request_id: _ } => BytesMut::new(),
            EndRequest {
                request_id: _,
                app_status,
                protocol_status,
            } => {
                let mut buf = BytesMut::with_capacity(8);
                buf.put_u32_be(app_status);
                buf.put_u8(protocol_status.as_number());
                buf.put_slice(&[0u8; 3]);
                buf
            }
            Params {
                request_id: _,
                body,
            } => body,
            StdIn {
                request_id: _,
                body,
            } => body,
            StdOut {
                request_id: _,
                body,
            } => body,
            StdErr {
                request_id: _,
                body,
            } => body,
            Data {
                request_id: _,
                body,
            } => body,
            GetValues { body } => body,
            GetValuesResult { body } => body,
            UnknownType { type_number } => {
                let mut buf = BytesMut::with_capacity(8);
                buf.put_u8(type_number);
                buf.put_slice(&[0u8; 7]);
                buf
            }
        };

        assert!(
            body.len() <= u16::max_value() as usize,
            "Fcgi record body size exceeded"
        );

        let mut header = BytesMut::with_capacity(HEADER_LEN);

        header.put_u8(1); // version
        header.put_u8(item_type_number);
        header.put_u16_be(request_id);
        header.put_u16_be(body.len() as u16);
        header.put_u8(0); // padding
        header.put_u8(0);

        self.queued_bytes += HEADER_LEN + body.len();
        self.write_queue.push_back(header);
        self.write_queue.push_back(body);

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        while let Some(front) = self.write_queue.front_mut() {
            let n = try_ready!(self.socket.poll_write(front));

            // As long as the write buffer is not empty, a successful write should never write 0
            // bytes.
            assert!(0 < n);

            front.advance(n);
            self.queued_bytes -= n;

            if front.is_empty() {
                self.write_queue.pop_front();
            }
        }

        Ok(Async::Ready(()))
    }
}
