use crate::helpers::parse_be_u16;
use crate::labels::Labels;
use ::bytes::{BufMut, BytesMut};
use nom::{
    error::{Error, ErrorKind},
    IResult,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RecordType {
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
pub enum RecordClass {
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Query {
    pub labels: Labels,
    pub record_type: RecordType,
    pub record_class: RecordClass,
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
