use crate::helpers::{parse_be_u16, parse_be_u32};
use crate::labels::Labels;
use crate::query::{RecordClass, RecordType};
use ::bytes::{BufMut, BytesMut};
use nom::{bytes::complete as bytes, IResult};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Answer {
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

    pub fn write_to(self: &Self, buffer: &mut BytesMut) -> anyhow::Result<()> {
        self.labels.write_to(buffer)?;
        self.record_type.write_to(buffer);
        self.record_class.write_to(buffer);
        buffer.put_u32(self.ttl);
        buffer.put_u16(
            u16::try_from(self.data.len())
                .expect("Implementation should have ensured that data is not too long"),
        );
        buffer.put(&self.data[..]);
        Ok(())
    }
}

#[test]
fn test_answer_creation() {
    use crate::labels::Label;

    let answer = Answer::with_ipv4(
        Labels::from_str("www.google.com").expect("Creating label should have succeeded"),
        RecordType::A,
        RecordClass::IN,
        99,
        0xAABBCCDD,
    );
    assert_eq!(answer.labels.len(), 3);
    assert_eq!(
        answer.labels[0],
        Label::from_str("www").expect("This should be a valid label")
    );
    assert_eq!(
        answer.labels[1],
        Label::from_str("google").expect("This should be a valid label")
    );
    assert_eq!(
        answer.labels[2],
        Label::from_str("com").expect("This should be a valid label")
    );
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
