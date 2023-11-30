#![deny(elided_lifetimes_in_paths)]

use std::net::UdpSocket;
use ::bytes::{BytesMut, BufMut};
use nom::{
    IResult,
    bits::complete as bits,
    bytes::complete as bytes, 
    error::Error
};

fn parse_be_u16(bytes: &[u8]) -> IResult<&[u8], u16>
{
    let (rest, bytes) = bytes::take(2usize)(bytes)?;
    Ok((rest, u16::from_be_bytes(bytes.try_into().expect("Taken 2 bytes, so should be fine to convert to [u8; 2]"))))
}

#[derive(Debug, Clone, Copy)]
enum Opcode
{
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

#[derive(Debug, Clone, Copy)]
enum ResponseCode
{
    NoError = 0,
}

#[derive(Debug, Clone, Copy)]
struct Header
{
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

impl Header
{
    pub fn reply(request_header: &Header, response_code: ResponseCode) -> Header
    {
        Header {
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
            additional_record_count: 0
        }
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self>
    {
        let (bytes, packet_id) = parse_be_u16(bytes)?;
        let (bytes, (is_reply, opcode, is_authoritative, truncation, recursion_desired, recursion_available, _, response_code)) = 
            nom::bits(nom::sequence::tuple((bits::bool, Self::parse_opcode, bits::bool, bits::bool, bits::bool, bits::bool, bits::tag(0, 3usize), Self::parse_response_code)))(bytes)?;

        let (bytes, question_count) = parse_be_u16(bytes)?;
        let (bytes, answer_record_count) = parse_be_u16(bytes)?;
        let (bytes, authority_record_count) = parse_be_u16(bytes)?;
        let (bytes, additional_record_count) = parse_be_u16(bytes)?;
        Ok((bytes, Header{
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
            additional_record_count
        }))
    }

    pub fn write_to(self: &Self, buffer: &mut BytesMut)
    {
        let mut flags = 0u16;

        if self.is_reply { flags |= 0x8000; }

        flags |= ((self.opcode as u16) & 0x0F) << 14;

        if self.is_authoritative {  flags |= 0x0400; }
        if self.truncation {  flags |= 0x0200; }
        if self.recursion_desired {  flags |= 0x0100; }
        if self.recursion_available {  flags |= 0x0080; }
        flags |= (self.response_code as u16) & 0x0F;

        buffer.put_u16_ne(self.packet_id);
        buffer.put_u16_ne(flags);
        buffer.put_u16_ne(self.question_count);
        buffer.put_u16_ne(self.answer_record_count);
        buffer.put_u16_ne(self.authority_record_count);
        buffer.put_u16_ne(self.additional_record_count);
    }

    fn parse_opcode(bits: (&[u8], usize)) -> IResult<(&[u8], usize), Opcode>
    {
        let (bits, opcode_bytes) = bits::take(4usize)(bits)?;
        let opcode = match opcode_bytes
        {
            0 => Ok(Opcode::Query),
            1 => Ok(Opcode::IQuery),
            2 => Ok(Opcode::Status),
            4 => Ok(Opcode::Notify),
            5 => Ok(Opcode::Update),
            _ => Err(nom::Err::Failure(Error::new(bits, nom::error::ErrorKind::Fail)))
        }?;
        Ok((bits, opcode))
    }

    fn parse_response_code(bits: (&[u8], usize)) -> IResult<(&[u8], usize), ResponseCode>
    {
        let (bits, opcode_bytes) = bits::take(4usize)(bits)?;
        let opcode = match opcode_bytes
        {
            0 => Ok(ResponseCode::NoError),
            _ => Err(nom::Err::Failure(Error::new(bits, nom::error::ErrorKind::Fail)))
        }?;
        Ok((bits, opcode))
    }
}

fn main() -> anyhow::Result<()> {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    eprintln!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let data = Vec::from(&buf[0..size]);
                // let _received_data = String::from_utf8_lossy(&buf[0..size]);
                eprintln!("Received {} bytes from {}", data.len(), source);
                match Header::parse(&data)
                {
                    Ok((rest, header)) => {
                        eprintln!("Header: {:?}, rest: {}", header, rest.len());

                        let mut response = BytesMut::with_capacity(12);
                        Header::reply(&header, ResponseCode::NoError).write_to(&mut response);

                        udp_socket
                            .send_to(&response, source)
                            .expect("Failed to send response");
                    }
                    Err(e) => {
                        eprintln!("Failed to parse header! {:?}", e);
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
