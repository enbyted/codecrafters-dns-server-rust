#![deny(elided_lifetimes_in_paths)]

use ::bytes::{BufMut, BytesMut};
use nom::{
    bits::complete as bits,
    bytes::complete as bytes,
    error::{Error, ErrorKind, FromExternalError},
    AsBytes, IResult,
};
use std::net::UdpSocket;
use std::str;

fn parse_be_u16(bytes: &[u8]) -> IResult<&[u8], u16> {
    let (rest, bytes) = bytes::take(2usize)(bytes)?;
    Ok((
        rest,
        u16::from_be_bytes(
            bytes
                .try_into()
                .expect("Taken 2 bytes, so should be fine to convert to [u8; 2]"),
        ),
    ))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ResponseCode {
    NoError = 0,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct Header {
    /// A random ID assigned to query packets. Response packets must reply with the same ID.
    packet_id: u16,
    /// True for a reply, false for question.
    is_reply: bool,
    /// Specifies kind of query in message.
    opcode: Opcode,
    /// True if the server "owns" the queried domain.
    is_authoritative: bool,
    /// True if the message is larger than 512 bytes, always false for UDP messages.
    truncation: bool,
    /// Sender sets this to true if the server should recursively resolve this query, false otherwise.
    recursion_desired: bool,
    /// Server sets this to true to indicate that recursion is available
    recursion_available: bool,
    /// Response code indicating the status of the response.
    response_code: ResponseCode,
    /// Number of questions in the Question section.
    question_count: u16,
    /// Number of records in the Answer section.
    answer_record_count: u16,
    /// Number of records in the Authority section.
    authority_record_count: u16,
    /// Number of records in the Additional section.
    additional_record_count: u16,
}

impl Header {
    pub fn reply(request_header: &Header, response_code: ResponseCode) -> Self {
        Self {
            packet_id: request_header.packet_id,
            is_reply: true,
            opcode: request_header.opcode,
            is_authoritative: false,
            truncation: false,
            recursion_desired: request_header.recursion_desired,
            recursion_available: false,
            response_code,
            question_count: 0,
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: 0,
        }
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (bytes, packet_id) = parse_be_u16(bytes)?;
        let (
            bytes,
            (
                is_reply,
                opcode,
                is_authoritative,
                truncation,
                recursion_desired,
                recursion_available,
                _,
                response_code,
            ),
        ) = nom::bits(nom::sequence::tuple((
            bits::bool,
            Self::parse_opcode,
            bits::bool,
            bits::bool,
            bits::bool,
            bits::bool,
            bits::tag(0, 3usize),
            Self::parse_response_code,
        )))(bytes)?;

        let (bytes, question_count) = parse_be_u16(bytes)?;
        let (bytes, answer_record_count) = parse_be_u16(bytes)?;
        let (bytes, authority_record_count) = parse_be_u16(bytes)?;
        let (bytes, additional_record_count) = parse_be_u16(bytes)?;
        Ok((
            bytes,
            Self {
                packet_id,
                is_reply,
                opcode,
                is_authoritative,
                truncation,
                recursion_desired,
                recursion_available,
                response_code,
                question_count,
                answer_record_count,
                authority_record_count,
                additional_record_count,
            },
        ))
    }

    pub fn write_to(self: &Self, buffer: &mut BytesMut) {
        let mut flags = 0u16;

        if self.is_reply {
            flags |= 0x8000;
        }

        flags |= ((self.opcode as u16) & 0x0F) << 11;

        if self.is_authoritative {
            flags |= 0x0400;
        }
        if self.truncation {
            flags |= 0x0200;
        }
        if self.recursion_desired {
            flags |= 0x0100;
        }
        if self.recursion_available {
            flags |= 0x0080;
        }
        flags |= (self.response_code as u16) & 0x0F;

        buffer.put_u16(self.packet_id);
        buffer.put_u16(flags);
        buffer.put_u16(self.question_count);
        buffer.put_u16(self.answer_record_count);
        buffer.put_u16(self.authority_record_count);
        buffer.put_u16(self.additional_record_count);
    }

    fn parse_opcode(bits: (&[u8], usize)) -> IResult<(&[u8], usize), Opcode> {
        let (bits, opcode_bytes) = bits::take(4usize)(bits)?;
        let opcode = match opcode_bytes {
            0 => Ok(Opcode::Query),
            1 => Ok(Opcode::IQuery),
            2 => Ok(Opcode::Status),
            4 => Ok(Opcode::Notify),
            5 => Ok(Opcode::Update),
            _ => Err(nom::Err::Failure(Error::new(
                bits,
                nom::error::ErrorKind::Fail,
            ))),
        }?;
        Ok((bits, opcode))
    }

    fn parse_response_code(bits: (&[u8], usize)) -> IResult<(&[u8], usize), ResponseCode> {
        let (bits, opcode_bytes) = bits::take(4usize)(bits)?;
        let opcode = match opcode_bytes {
            0 => Ok(ResponseCode::NoError),
            _ => Err(nom::Err::Failure(Error::new(bits, ErrorKind::Fail))),
        }?;
        Ok((bits, opcode))
    }
}

#[test]
fn test_serialize_deserialize_header_gets_same_result() {
    let header = Header {
        packet_id: 1234,
        is_reply: false,
        opcode: Opcode::Notify,
        truncation: false,
        recursion_desired: true,
        recursion_available: false,
        is_authoritative: false,
        response_code: ResponseCode::NoError,
        question_count: 1,
        answer_record_count: 2,
        authority_record_count: 3,
        additional_record_count: 4,
    };
    let mut bytes = BytesMut::new();
    header.write_to(&mut bytes);

    eprintln!("{:?}", bytes.as_bytes());

    assert_eq!(header, Header::parse(bytes.as_bytes()).unwrap().1);
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RecordType {
    A = 1,
    CNAME = 5,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RecordClass {
    IN = 1,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Query<'a> {
    labels: Vec<&'a str>,
    record_type: RecordType,
    record_class: RecordClass,
}

impl Query<'_> {
    pub fn new<'a>(url: &'a str, record_type: RecordType, record_class: RecordClass) -> Query<'a> {
        Query {
            labels: url.split('.').collect(),
            record_type,
            record_class,
        }
    }

    pub fn parse<'a>(bytes: &'a [u8]) -> IResult<&'a [u8], Query<'a>> {
        let mut bytes = bytes;
        let mut labels = Vec::<&'a str>::new();
        loop {
            let (rest, label) = Self::parse_label(bytes)?;
            bytes = rest;
            if label.len() == 0 {
                break;
            }
            labels.push(label);
        }
        let (bytes, record_type) = Self::parse_record_type(bytes)?;
        let (bytes, record_class) = Self::parse_record_class(bytes)?;

        Ok((
            bytes,
            Query {
                labels,
                record_type,
                record_class,
            },
        ))
    }

    pub fn write_to(self: &Self, buffer: &mut BytesMut) -> anyhow::Result<()> {
        for &label in self.labels.iter() {
            let len = u8::try_from(label.len())?;
            buffer.put_u8(len);
            buffer.put_slice(label.as_bytes());
        }

        // The last 0-length label
        buffer.put_u8(0);
        buffer.put_u8(self.record_type as u8);
        buffer.put_u8(self.record_class as u8);

        Ok(())
    }

    fn parse_label(bytes: &[u8]) -> IResult<&[u8], &str> {
        let (bytes, length) = bytes::take(1usize)(bytes)?;
        assert_eq!(length.len(), 1);
        let length = length[0] as usize;
        let (bytes, label_bytes) = bytes::take(length)(bytes)?;
        let label = str::from_utf8(label_bytes).map_err(|e| {
            nom::Err::Error(nom::error::Error::from_external_error(
                bytes,
                ErrorKind::Fail,
                e,
            ))
        })?;

        Ok((bytes, label))
    }

    fn parse_record_type(bytes: &[u8]) -> IResult<&[u8], RecordType> {
        let (bytes, record_type_byte) = bytes::take(1usize)(bytes)?;
        assert_eq!(record_type_byte.len(), 1);
        let record_type_byte = record_type_byte[0];
        let record_type = match record_type_byte {
            1 => Ok(RecordType::A),
            5 => Ok(RecordType::CNAME),
            _ => Err(nom::Err::Error(Error::new(bytes, ErrorKind::Fail))),
        }?;
        Ok((bytes, record_type))
    }

    fn parse_record_class(bytes: &[u8]) -> IResult<&[u8], RecordClass> {
        let (bytes, record_type_byte) = bytes::take(1usize)(bytes)?;
        assert_eq!(record_type_byte.len(), 1);
        let record_type_byte = record_type_byte[0];
        let record_type = match record_type_byte {
            1 => Ok(RecordClass::IN),
            _ => Err(nom::Err::Error(Error::new(bytes, ErrorKind::Fail))),
        }?;
        Ok((bytes, record_type))
    }
}

fn handle_message<'a>(payload: &'a [u8], response_buffer: &mut BytesMut) -> IResult<&'a [u8], ()> {
    let (payload, header) = Header::parse(payload)?;
    eprintln!("Received header: {:?}", header);

    let mut queries = Vec::<Query<'_>>::new();

    let mut payload = payload;
    for _ in 0..header.question_count {
        let (rest, query) = Query::parse(payload)?;
        payload = rest;
        eprintln!("Received query: {:?}", query);
        queries.push(query);
    }

    response_buffer.clear();
    let mut reply_header = Header::reply(&header, ResponseCode::NoError);
    reply_header.question_count = 1;
    eprintln!("Reply header: {:?}", reply_header);
    reply_header.write_to(response_buffer);

    let reply_query = Query::new("google.com", RecordType::A, RecordClass::IN);
    eprintln!("Reply qyery: {:?}", reply_query);
    reply_query
        .write_to(response_buffer)
        .expect("We've provided valid data in code, this should always succeed");

    Ok((payload, ()))
}

fn main() -> anyhow::Result<()> {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    eprintln!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
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
