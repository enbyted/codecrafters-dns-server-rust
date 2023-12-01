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

    pub fn write_to(self: &Self, buffer: &mut BytesMut) -> anyhow::Result<()> {
        self.labels.write_to(buffer)?;
        self.record_type.write_to(buffer);
        self.record_class.write_to(buffer);
        Ok(())
    }
}

#[test]
fn test_query_creation() {
    use crate::labels::Label;

    let query = Query::new("www.google.com", RecordType::A, RecordClass::IN)
        .expect("Creating should succeed");
    assert_eq!(query.labels.len(), 3);
    assert_eq!(
        query.labels[0],
        Label::from_str("www").expect("this is a valid label, so it should succeed")
    );
    assert_eq!(
        query.labels[1],
        Label::from_str("google").expect("this is a valid label, so it should succeed")
    );
    assert_eq!(
        query.labels[2],
        Label::from_str("com").expect("this is a valid label, so it should succeed")
    );
    assert_eq!(query.record_type, RecordType::A);
    assert_eq!(query.record_class, RecordClass::IN);
}

#[test]
fn test_serialize_deserialize_query_gets_the_same_result() {
    let query = Query::new("www.google.com", RecordType::A, RecordClass::IN)
        .expect("Creating should succeed");
    let mut buf = BytesMut::new();
    query
        .write_to(&mut buf)
        .expect("Writing should have succeeded");
    let (leftover, parsed_query) = Query::parse(&buf).expect("Decoding should go fine");
    assert!(leftover.is_empty());
    assert_eq!(query, parsed_query);
}

#[test]
fn test_real_query_from_stage_7() {
    let bytes: [u8; 41 + 12] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x3, 0x61, 0x62, 0x63, 0x11, 0x6C, 0x6F, 0x6E, 0x67,
        0x61, 0x73, 0x73, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x6E, 0x61, 0x6D, 0x65, 0x3, 0x63,
        0x6F, 0x6D, 0x0, 0x0, 0x1, 0x0, 0x1, 0x3, 0x64, 0x65, 0x66, 0xC0, 0x10, 0x0, 0x1, 0x0, 0x1,
    ];
    let (rest, query1) = Query::parse(&bytes[12..]).expect("parsing should work");
    eprintln!("Query1: {:?}", query1);
    eprintln!("Rest: {:X?}", rest);
    let (rest, mut query2) = Query::parse(&rest).expect("parsing should work");
    eprintln!("Query2: {:?}", query2);

    assert!(query1.labels.is_decompressed());
    assert!(!query2.labels.is_decompressed());
    query2
        .labels
        .decompress(&query1.labels, bytes.as_ptr() as usize);

    let mut buf = BytesMut::new();
    query1.write_to(&mut buf).expect("Writing should succeed");
    query2.write_to(&mut buf).expect("Writing should succeed");
    eprintln!("Written bytes: {:?}", buf);
}
