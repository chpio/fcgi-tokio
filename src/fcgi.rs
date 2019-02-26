use bytes::{Buf, BufMut, Bytes, BytesMut, IntoBuf};
use bytes_queue::BytesQueue;
use futures::{sync::mpsc, try_ready, Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use std::io::Cursor;
use tokio::io::{self, AsyncRead, AsyncWrite};

const HEADER_LEN: usize = 8;
const WRITE_SOFT_LIMIT: usize = 16 * 1024;

#[derive(Debug, Eq, PartialEq)]
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

#[derive(Debug, Eq, PartialEq)]
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
        body: Bytes,
    },
    StdIn {
        request_id: u16,
        body: Bytes,
    },
    StdOut {
        request_id: u16,
        body: Bytes,
    },
    StdErr {
        request_id: u16,
        body: Bytes,
    },
    Data {
        request_id: u16,
        body: Bytes,
    },
    GetValues {
        body: Bytes,
    },
    GetValuesResult {
        body: Bytes,
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

        let buf = read_buf
            .split_to(state.body_padding_len - state.padding_len as usize)
            .freeze();
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
    write_queue: BytesQueue<Cursor<Bytes>>,
}

impl<S> FcgiEncoder<S>
where
    S: AsyncWrite,
{
    pub fn new(writer: S) -> FcgiEncoder<S> {
        FcgiEncoder {
            socket: writer,
            write_queue: BytesQueue::new(),
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

        if WRITE_SOFT_LIMIT <= self.write_queue.remaining()
            && self.poll_complete()?.is_not_ready()
            && WRITE_SOFT_LIMIT <= self.write_queue.remaining()
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
                buf.freeze()
            }
            AbortRequest { request_id: _ } => Bytes::new(),
            EndRequest {
                request_id: _,
                app_status,
                protocol_status,
            } => {
                let mut buf = BytesMut::with_capacity(8);
                buf.put_u32_be(app_status);
                buf.put_u8(protocol_status.as_number());
                buf.put_slice(&[0u8; 3]);
                buf.freeze()
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
                buf.freeze()
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

        self.write_queue.push(header.freeze().into_buf());
        self.write_queue.push(body.into_buf());

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        while self.write_queue.has_remaining() {
            try_ready!(self.socket.write_buf(&mut self.write_queue));
        }
        Ok(Async::Ready(()))
    }
}

const MAX_REQUEST_ID: u16 = 10_000;

struct ServerHandler<R, HF> {
    reader: FcgiDecoder<R>,
    encoder_tx: mpsc::Sender<Record>,
    handler_txes: Vec<Option<mpsc::Sender<Record>>>,
    handler_management: mpsc::Sender<Record>,
    next_record: Option<Record>,
    handler_factory: HF,
}

impl<R, HF, HFR> ServerHandler<R, HF>
where
    R: AsyncRead + Send,
    HF: FnMut(mpsc::Receiver<Record>) -> HFR,
    HFR: Stream<Item = Record, Error = ()> + Send + 'static,
{
    fn handle_record(&mut self, record: Record) -> Async<()> {
        let request_id = record.request_id() as usize;

        if request_id == 0 {
            // TODO: put handler_management into handler_txes?
            if let Err(e) = self.handler_management.try_send(record) {
                if e.is_disconnected() {
                    // TODO: return error?
                } else if e.is_full() {
                    self.next_record = Some(e.into_inner());
                    return Async::NotReady;
                } else {
                    unreachable!();
                }
            }
        } else {
            if let Some(handler_tx_opt) = self.handler_txes.get_mut(request_id) {
                if let Some(handler_tx) = handler_tx_opt.as_mut() {
                    if let Err(e) = handler_tx.try_send(record) {
                        if e.is_disconnected() {
                            *handler_tx_opt = None;
                        } else if e.is_full() {
                            self.next_record = Some(e.into_inner());
                            return Async::NotReady;
                        } else {
                            unreachable!();
                        }
                    }
                }
            }
        }

        Async::Ready(())
    }
}

impl<R, F, FR> Future for ServerHandler<R, F>
where
    R: AsyncRead + Send,
    F: FnMut(mpsc::Receiver<Record>) -> FR,
    FR: Stream<Item = Record, Error = ()> + Send + 'static,
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(record) = self.next_record.take() {
            if self.handle_record(record).is_not_ready() {
                return Ok(Async::NotReady);
            }
        }

        loop {
            let record = try_ready!(self.reader.poll());
            let record = if let Some(record) = record {
                record
            } else {
                // End of Stream
                return Ok(Async::Ready(()));
            };

            if let Record::BeginRequest { request_id, .. } = &record {
                assert!(*request_id <= MAX_REQUEST_ID);

                let request_id = *request_id as usize;

                // fill handler slots
                if self.handler_txes.len() <= request_id {
                    let new = 0..(request_id - self.handler_txes.len() + 1);
                    let new = new.map(|_| None);
                    self.handler_txes.extend(new);
                }
                let handler_tx = self.handler_txes.get_mut(request_id).unwrap();

                let (tx, rx) = mpsc::channel(8);
                tokio::spawn(
                    (self.handler_factory)(rx)
                        .forward(self.encoder_tx.clone().sink_map_err(|_| ()))
                        .map(|_| ()),
                );
                *handler_tx = Some(tx);
            }

            if self.handle_record(record).is_not_ready() {
                return Ok(Async::NotReady);
            }
        }
    }
}

pub fn server_handler<R, W, HF, HFR, MF, MFR>(
    reader: R,
    writer: W,
    management_factory: MF,
    handler_factory: HF,
) where
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
    HF: FnMut(mpsc::Receiver<Record>) -> HFR + Send + 'static,
    HFR: Stream<Item = Record, Error = ()> + Send + 'static,
    MF: FnOnce(mpsc::Receiver<Record>) -> MFR + Send + 'static,
    MFR: Stream<Item = Record, Error = ()> + Send + 'static,
{
    let (encoder_tx, encoder_rx) = mpsc::channel(8);

    let (management_tx, management_rx) = mpsc::channel(8);
    tokio::spawn(
        management_factory(management_rx)
            .forward(encoder_tx.clone().sink_map_err(|_| ()))
            .map(|_| ()),
    );

    tokio::spawn(
        ServerHandler {
            reader: FcgiDecoder::new(reader),
            encoder_tx,
            handler_txes: Vec::new(),
            handler_management: management_tx,
            next_record: None,
            handler_factory,
        }
        .map_err(|_| ()),
    );

    tokio::spawn(
        encoder_rx
            .forward(FcgiEncoder::new(writer).sink_map_err(|_| ()))
            .map(|_| ()),
    );
}
