use ::bytes::BytesMut;
use anyhow::anyhow;
use dns_starter_rust::answer::Answer;
use dns_starter_rust::dns::Request;
use dns_starter_rust::header::{Opcode, ResponseCode};
use dns_starter_rust::query::Query;
use nom::error::{Error, ErrorKind, FromExternalError};
use nom::IResult;
use rand::random;
use std::env;
use std::net::{Ipv4Addr, UdpSocket};

trait Resolver {
    fn resolve(&self, query: &Query) -> anyhow::Result<Vec<Answer>>;
}

struct DemoResolver;

impl Resolver for DemoResolver {
    fn resolve(&self, query: &Query) -> anyhow::Result<Vec<Answer>> {
        Ok(vec![Answer::with_ipv4(
            query.labels.clone(),
            query.record_type,
            query.record_class,
            11,
            0x01020304,
        )])
    }
}

struct ForwardingResolver {
    socket: UdpSocket,
}

impl Resolver for ForwardingResolver {
    fn resolve(&self, query: &Query) -> anyhow::Result<Vec<Answer>> {
        eprintln!("Resolving {} externally", query.labels.to_string());
        let mut request = Request::new(random(), Opcode::Query);
        request.add_query(query.clone());
        let mut buffer = BytesMut::new();
        request.write_to(&mut buffer)?;
        self.socket.send(&buffer)?;

        buffer.resize(512, 0);
        let received_bytes = self.socket.recv(&mut buffer)?;
        anyhow::ensure!(received_bytes <= buffer.len());
        buffer.resize(received_bytes, 0);
        let (_, response) = Request::parse(&buffer).map_err(|e| e.to_owned())?;
        anyhow::ensure!(response.header().packet_id == request.header().packet_id);
        anyhow::ensure!(response.header().response_code == ResponseCode::NoError);
        Ok(response.answers_iter().map(|a| a.clone()).collect())
    }
}

impl ForwardingResolver {
    fn new(address: &str) -> anyhow::Result<ForwardingResolver> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect(address)?;
        Ok(ForwardingResolver { socket })
    }
}

fn handle_message<'a>(
    payload: &'a [u8],
    response_buffer: &mut BytesMut,
    resolver: &dyn Resolver,
) -> IResult<&'a [u8], ()> {
    let base_offset = payload.as_ptr() as usize;
    eprintln!(
        "Received bytes: {:X?}, base_offset: {:?}",
        payload, base_offset
    );
    let (payload, request) = Request::parse(payload)?;
    eprintln!("Received request: {:?}", request);
    eprintln!("Remaining bytes: {:X?}", payload);

    response_buffer.clear();

    match request.header().opcode {
        Opcode::Query => {
            let mut reply = Request::reply(&request, ResponseCode::NoError);

            for query in request.queries_iter() {
                eprintln!("Reply query: {:?}", query);
                let answers = resolver.resolve(&query).map_err(|e| {
                    nom::Err::Failure(Error::from_external_error(payload, ErrorKind::Fail, e))
                })?;
                for answer in answers {
                    reply.add_answer(answer);
                }
            }

            eprintln!("Reply: {:?}", reply);
            reply.write_to(response_buffer).map_err(|e| {
                nom::Err::Failure(Error::from_external_error(payload, ErrorKind::Fail, e))
            })?;
        }
        _ => {
            let reply = Request::reply(&request, ResponseCode::NotImplemented);
            reply.write_to(response_buffer).map_err(|e| {
                nom::Err::Failure(Error::from_external_error(payload, ErrorKind::Fail, e))
            })?;
        }
    }

    eprintln!("Encoded bytes: {:X?}", response_buffer);
    Ok((payload, ()))
}

fn main() -> anyhow::Result<()> {
    eprintln!("Enbyted's implementation of a simple DNS server!");

    let args: Vec<_> = env::args().collect();

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf: [u8; 512] = [0; 512];
    let mut response_buffer = BytesMut::new();

    let resolver: Box<dyn Resolver> = match args.as_slice() {
        [_] => Ok(Box::new(DemoResolver) as Box<dyn Resolver>),
        [_, resolver, address] => {
            if resolver != "--resolver" {
                eprintln!("Usage ./your_server.sh [--resolver <ip>:<port>]");
                anyhow::bail!("Invalid arguments");
            }
            Ok(Box::new(ForwardingResolver::new(address.as_str())?) as Box<dyn Resolver>)
        }
        _ => {
            eprintln!("Usage ./your_server.sh [--resolver <ip>:<port>]");
            Err(anyhow!("Invalid arguments"))
        }
    }?;

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                eprintln!("Received {} bytes from {}", size, source);
                match handle_message(&buf[0..size], &mut response_buffer, resolver.as_ref()) {
                    Ok(_) => {
                        eprintln!("Sending {} bytes reply", response_buffer.len());
                        udp_socket
                            .send_to(&response_buffer, source)
                            .expect("Failed to send response");
                    }
                    Err(e) => {
                        eprintln!("Error while processing message: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break Ok(());
            }
        }
    }
}
