pub mod fcgi;
pub mod params;
pub mod varint;

use bytes::Bytes;
use fcgi::{ProtocolStatus, Record};
use futures::future::Future;
use futures::stream::{iter_ok, Stream};
use params::ParamsDecoder;
use tokio::io::AsyncRead;
use tokio::net::TcpListener;

fn main() {
    let addr = "127.0.0.1:9000".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    let server = listener
        .incoming()
        .for_each(|socket| {
            println!("new connection");
            let (reader, writer) = socket.split();
            fcgi::server_handler(
                reader,
                writer,
                |stream| {
                    stream.filter(|r| {
                        println!("{:?}", r);
                        false
                    })
                },
                |stream| {
                    let mut params_dec = ParamsDecoder::<Vec<(String, String)>>::new();

                    stream
                        .filter_map(move |record| {
                            println!("{:?}", record);

                            if let Record::Params { body } = record {
                                if let Some(params) = params_dec.decode(body) {
                                    println!("params: {:?}", params);

                                    return Some(iter_ok(vec![
                                        Record::StdOut {
                                            body: Bytes::from_static(
                                                b"Content-type: text/html\r\n\r\nFOOBAR",
                                            ),
                                        },
                                        Record::StdOut { body: Bytes::new() },
                                        Record::EndRequest {
                                            app_status: 0,
                                            protocol_status: ProtocolStatus::RequestComplete,
                                        },
                                    ]));
                                }
                            }

                            None
                        })
                        .flatten()
                },
            );
            Ok(())
        })
        .map_err(|err| {
            println!("accept error = {:?}", err);
        });

    tokio::run(server);
}
