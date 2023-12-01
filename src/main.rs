#![deny(elided_lifetimes_in_paths)]

use ::bytes::{BufMut, BytesMut};
use nom::{
    bits::complete as bits,
    bytes::complete as bytes,
    error::{Error, ErrorKind, FromExternalError},
    AsBytes, IResult,
};
use std::{net::UdpSocket, str::FromStr};
use std::{ops::Index, str};

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
fn parse_be_u32(bytes: &[u8]) -> IResult<&[u8], u32> {
    let (rest, bytes) = bytes::take(4usize)(bytes)?;
    Ok((
        rest,
        u32::from_be_bytes(
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

impl RecordType {
    pub fn parse<'a>(bytes: &'a [u8]) -> IResult<&'a [u8], RecordType> {
        let (bytes, record_type_byte) = parse_be_u16(bytes)?;
        let record_type = match record_type_byte {
            1 => Ok(RecordType::A),
            5 => Ok(RecordType::CNAME),
            _ => Err(nom::Err::Error(Error::new(bytes, ErrorKind::Fail))),
        }?;
        Ok((bytes, record_type))
    }

    pub fn write_to(self: &Self, buffer: &mut BytesMut) {
        buffer.put_u16(*self as u16);
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RecordClass {
    IN = 1,
}

impl RecordClass {
    pub fn parse<'a>(bytes: &'a [u8]) -> IResult<&'a [u8], RecordClass> {
        let (bytes, record_type_byte) = parse_be_u16(bytes)?;
        let record_class = match record_type_byte {
            1 => Ok(RecordClass::IN),
            _ => Err(nom::Err::Error(Error::new(bytes, ErrorKind::Fail))),
        }?;
        Ok((bytes, record_class))
    }

    pub fn write_to(self: &Self, buffer: &mut BytesMut) {
        buffer.put_u16(*self as u16);
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Eq, PartialEq)]
struct Labels {
    labels: Vec<String>,
}

impl Index<usize> for Labels {
    type Output = String;
    fn index<'a>(&'a self, i: usize) -> &'a String {
        return &self.labels[i];
    }
}

impl Labels {
    pub fn from_str(text: &str) -> anyhow::Result<Labels> {
        let mut labels = Vec::new();
        for label in text.split('.') {
            anyhow::ensure!(label.len() <= u8::MAX as usize);
            anyhow::ensure!(label.len() > 0);

            labels.push(String::from_str(label)?);
        }
        Ok(Labels { labels })
    }

    pub fn parse<'a>(bytes: &'a [u8]) -> IResult<&'a [u8], Labels> {
        let mut bytes = bytes;
        let mut labels = Vec::<String>::new();
        loop {
            let (rest, label) = Self::parse_label(bytes)?;
            bytes = rest;
            if label.len() == 0 {
                break;
            }
            let label = String::from_str(label).expect(
                "This should always succeeed as label was already checkd to be a valid string",
            );
            labels.push(label);
        }

        Ok((bytes, Labels { labels }))
    }

    pub fn write_to(&self, buffer: &mut BytesMut) {
        for label in self.labels.iter() {
            let len = u8::try_from(label.len()).expect("The struct implementation should have made sure that we have labels of valid length");
            buffer.put_u8(len);
            buffer.put_slice(label.as_bytes());
        }

        // The last 0-length label
        buffer.put_u8(0);
    }

    pub fn len(&self) -> usize {
        self.labels.len()
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
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Query {
    labels: Labels,
    record_type: RecordType,
    record_class: RecordClass,
}

impl Query {
    pub fn new<'a>(
        url: &str,
        record_type: RecordType,
        record_class: RecordClass,
    ) -> anyhow::Result<Query> {
        Ok(Query {
            labels: Labels::from_str(url)?,
            record_type,
            record_class,
        })
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Query> {
        let (bytes, labels) = Labels::parse(bytes)?;
        let (bytes, record_type) = RecordType::parse(bytes)?;
        let (bytes, record_class) = RecordClass::parse(bytes)?;

        Ok((
            bytes,
            Query {
                labels,
                record_type,
                record_class,
            },
        ))
    }

    pub fn write_to(self: &Self, buffer: &mut BytesMut) {
        self.labels.write_to(buffer);
        self.record_type.write_to(buffer);
        self.record_class.write_to(buffer);
    }
}

#[test]
fn test_query_creation() {
    let query = Query::new("www.google.com", RecordType::A, RecordClass::IN)
        .expect("Creating should succeed");
    assert_eq!(query.labels.len(), 3);
    assert_eq!(query.labels[0], "www");
    assert_eq!(query.labels[1], "google");
    assert_eq!(query.labels[2], "com");
    assert_eq!(query.record_type, RecordType::A);
    assert_eq!(query.record_class, RecordClass::IN);
}

#[test]
fn test_serialize_deserialize_query_gets_the_same_result() {
    let query = Query::new("www.google.com", RecordType::A, RecordClass::IN)
        .expect("Creating should succeed");
    let mut buf = BytesMut::new();
    query.write_to(&mut buf);
    let (leftover, parsed_query) = Query::parse(&buf).expect("Decoding should go fine");
    assert!(leftover.is_empty());
    assert_eq!(query, parsed_query);
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Answer {
    labels: Labels,
    record_type: RecordType,
    record_class: RecordClass,
    ttl: u32,
    data: Vec<u8>,
}

impl Answer {
    pub fn with_ipv4<'a>(
        labels: Labels,
        record_type: RecordType,
        record_class: RecordClass,
        ttl: u32,
        ip: u32,
    ) -> Answer {
        let mut data = Vec::with_capacity(4);
        data.put_u32(ip);
        Answer {
            labels,
            record_type,
            record_class,
            ttl,
            data,
        }
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Answer> {
        let (bytes, labels) = Labels::parse(bytes)?;
        let (bytes, record_type) = RecordType::parse(bytes)?;
        let (bytes, record_class) = RecordClass::parse(bytes)?;
        let (bytes, ttl) = parse_be_u32(bytes)?;
        let (bytes, data_length) = parse_be_u16(bytes)?;
        let (bytes, data) = bytes::take(data_length as usize)(bytes)?;

        Ok((
            bytes,
            Answer {
                labels,
                record_type,
                record_class,
                ttl,
                data: Vec::from(data),
            },
        ))
    }

    pub fn write_to(self: &Self, buffer: &mut BytesMut) {
        self.labels.write_to(buffer);
        self.record_type.write_to(buffer);
        self.record_class.write_to(buffer);
        buffer.put_u32(self.ttl);
        buffer.put_u16(
            u16::try_from(self.data.len())
                .expect("Implementation should have ensured that data is not too long"),
        );
        buffer.put(&self.data[..]);
    }
}

#[test]
fn test_answer_creation() {
    let answer = Answer::with_ipv4(
        Labels::from_str("www.google.com").expect("Creating label should have succeeded"),
        RecordType::A,
        RecordClass::IN,
        99,
        0xAABBCCDD,
    );
    assert_eq!(answer.labels.len(), 3);
    assert_eq!(answer.labels[0], "www");
    assert_eq!(answer.labels[1], "google");
    assert_eq!(answer.labels[2], "com");
    assert_eq!(answer.record_type, RecordType::A);
    assert_eq!(answer.record_class, RecordClass::IN);
    assert_eq!(answer.ttl, 99);
    assert_eq!(answer.data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn test_serialize_deserialize_answer_gets_the_same_result() {
    let answer = Answer::with_ipv4(
        Labels::from_str("www.google.com").expect("Creating label should have succeeded"),
        RecordType::A,
        RecordClass::IN,
        99,
        0xAABBCCDD,
    );
    let mut buf = BytesMut::new();
    answer.write_to(&mut buf);
    let (leftover, parsed_answer) = Answer::parse(&buf).expect("Decoding should go fine");
    assert!(leftover.is_empty());
    assert_eq!(answer, parsed_answer);
}

fn handle_message<'a>(payload: &'a [u8], response_buffer: &mut BytesMut) -> IResult<&'a [u8], ()> {
    let (payload, header) = Header::parse(payload)?;
    eprintln!("Received header: {:?}", header);
    eprintln!("Remaining bytes: {:X?}", payload);

    let mut queries = Vec::<Query>::new();

    let mut payload = payload;
    for _ in 0..header.question_count {
        let (rest, query) = Query::parse(payload)?;
        payload = rest;
        eprintln!("Received query: {:?}", query);
        eprintln!("Remaining bytes: {:X?}", payload);
        queries.push(query);
    }

    response_buffer.clear();
    let mut reply_header = Header::reply(&header, ResponseCode::NoError);
    reply_header.question_count = queries.len() as u16;
    reply_header.answer_record_count = queries.len() as u16;
    eprintln!("Reply header: {:?}", reply_header);
    reply_header.write_to(response_buffer);

    let mut answers = Vec::with_capacity(queries.len());
    for query in queries {
        eprintln!("Reply query: {:?}", query);
        query.write_to(response_buffer);
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

    eprintln!("Encoded bytes: {:X?}", response_buffer);
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
