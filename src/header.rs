use crate::helpers::parse_be_u16;
use ::bytes::{BufMut, BytesMut};
use nom::{
    bits::complete as bits,
    error::{Error, ErrorKind},
    IResult,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u16)]
pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    Unknown(u16),
}

impl Into<u16> for Opcode {
    fn into(self) -> u16 {
        match self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2,
            Self::Notify => 4,
            Self::Update => 5,
            Self::Unknown(code) => code,
        }
    }
}

impl From<u16> for Opcode {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u16)]
pub enum ResponseCode {
    NoError = 0,
    NotImplemented = 4,
    Unknown(u16),
}

impl Into<u16> for ResponseCode {
    fn into(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::NotImplemented => 4,
            Self::Unknown(code) => code,
        }
    }
}

impl From<u16> for ResponseCode {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::NoError,
            4 => Self::NotImplemented,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Header {
    /// A random ID assigned to query packets. Response packets must reply with the same ID.
    pub packet_id: u16,
    /// True for a reply, false for question.
    pub is_reply: bool,
    /// Specifies kind of query in message.
    pub opcode: Opcode,
    /// True if the server "owns" the queried domain.
    pub is_authoritative: bool,
    /// True if the message is larger than 512 bytes, always false for UDP messages.
    pub truncation: bool,
    /// Sender sets this to true if the server should recursively resolve this query, false otherwise.
    pub recursion_desired: bool,
    /// Server sets this to true to indicate that recursion is available
    pub recursion_available: bool,
    /// Response code indicating the status of the response.
    pub response_code: ResponseCode,
    /// Number of questions in the Question section.
    pub question_count: u16,
    /// Number of records in the Answer section.
    pub answer_record_count: u16,
    /// Number of records in the Authority section.
    pub authority_record_count: u16,
    /// Number of records in the Additional section.
    pub additional_record_count: u16,
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
            bits::take::<_, u8, _, _>(3usize),
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

        flags |= ((Into::<u16>::into(self.opcode)) & 0x0F) << 11;

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
        flags |= (Into::<u16>::into(self.response_code)) & 0x0F;

        buffer.put_u16(self.packet_id);
        buffer.put_u16(flags);
        buffer.put_u16(self.question_count);
        buffer.put_u16(self.answer_record_count);
        buffer.put_u16(self.authority_record_count);
        buffer.put_u16(self.additional_record_count);
    }

    fn parse_opcode(bits: (&[u8], usize)) -> IResult<(&[u8], usize), Opcode> {
        let (bits, opcode_bytes): (_, u16) = bits::take(4usize)(bits)?;
        let opcode = Opcode::from(opcode_bytes);
        Ok((bits, opcode))
    }

    fn parse_response_code(bits: (&[u8], usize)) -> IResult<(&[u8], usize), ResponseCode> {
        let (bits, response_code_bytes): (_, u16) = bits::take(4usize)(bits)?;
        let opcode = ResponseCode::from(response_code_bytes);
        Ok((bits, opcode))
    }
}

#[test]
fn test_serialize_deserialize_header_gets_same_result() {
    use nom::AsBytes;

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
