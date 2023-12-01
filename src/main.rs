use ::bytes::BytesMut;
use dns_starter_rust::answer::Answer;
use dns_starter_rust::header::{Header, Opcode, ResponseCode};
use dns_starter_rust::query::Query;
use nom::IResult;
use std::net::UdpSocket;

fn handle_message<'a>(payload: &'a [u8], response_buffer: &mut BytesMut) -> IResult<&'a [u8], ()> {
    let (payload, header) = Header::parse(payload)?;
    eprintln!("Received header: {:?}", header);
    eprintln!("Remaining bytes: {:X?}", payload);
    response_buffer.clear();

    match header.opcode {
        Opcode::Query => {
            let mut queries = Vec::<Query>::new();

            let base_offset = payload.as_ptr() as usize;
            let mut payload = payload;
            for _ in 0..header.question_count {
                let (rest, query) = Query::parse(payload)?;
                payload = rest;
                eprintln!("Received query: {:?}", query);
                eprintln!("Remaining bytes: {:X?}", payload);
                queries.push(query);
            }

            let mut reply_header = Header::reply(&header, ResponseCode::NoError);
            reply_header.question_count = queries.len() as u16;
            reply_header.answer_record_count = queries.len() as u16;
            eprintln!("Reply header: {:?}", reply_header);
            reply_header.write_to(response_buffer);

            let mut answers = Vec::with_capacity(queries.len());
            for i in 1..queries.len() {
                let (left, right) = queries.split_at_mut(i);
                for a in left.iter_mut() {
                    for b in right.iter_mut() {
                        a.labels.decompress(&b.labels, base_offset);
                        b.labels.decompress(&a.labels, base_offset);
                    }
                }
            }
            for query in queries.iter() {
                eprintln!("Decompressed query: {:?}", query);
            }

            for query in queries {
                eprintln!("Reply query: {:?}", query);
                query
                    .write_to(response_buffer)
                    .expect("Writing query should have succeeded");
                answers.push(Answer::with_ipv4(
                    query.labels,
                    query.record_type,
                    query.record_class,
                    1,
                    0x01020304,
                ));
            }

            for answer in answers {
                answer.write_to(response_buffer);
            }
        }
        _ => {
            let reply_header = Header::reply(&header, ResponseCode::NotImplemented);
            reply_header.write_to(response_buffer);
        }
    }

    eprintln!("Encoded bytes: {:X?}", response_buffer);
    Ok((payload, ()))
}

fn main() -> anyhow::Result<()> {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    eprintln!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf: [u8; 512] = [0; 512];
    let mut response_buffer = BytesMut::new();

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                eprintln!("Received {} bytes from {}", size, source);
                match handle_message(&buf[0..size], &mut response_buffer) {
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
