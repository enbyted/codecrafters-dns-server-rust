use ::bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete as bytes,
    error::{Error, ErrorKind, FromExternalError},
    IResult,
};
use std::{ops::Index, str, str::FromStr};

use crate::helpers::parse_be_u16;

#[derive(Debug, Clone, Eq)]
pub enum Label {
    Value { label: String, address: usize },
    Pointer { offset: usize },
}

impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Value { label: l_label, .. }, Self::Value { label: r_label, .. }) => {
                l_label == r_label
            }
            (Self::Pointer { offset: l_offset }, Self::Pointer { offset: r_offset }) => {
                l_offset == r_offset
            }
            _ => false,
        }
    }
}

impl Label {
    pub fn from_str(label: &str) -> anyhow::Result<Label> {
        Label::from_string(label.to_string())
    }

    pub fn from_string(label: String) -> anyhow::Result<Label> {
        anyhow::ensure!(label.len() <= 63 as usize);
        anyhow::ensure!(label.len() > 0);
        Ok(Label::Value { label, address: 0 })
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Label> {
        nom::branch::alt((Self::parse_value, Self::parse_pointer))(bytes)
    }

    pub fn write_to(&self, buffer: &mut BytesMut) -> anyhow::Result<()> {
        match self {
            Label::Value { label, .. } => {
                anyhow::ensure!(label.len() <= 63);
                buffer
                    .put_u8(u8::try_from(label.len()).expect(
                        "Value has been checked for size, so should be fine to cast to u8",
                    ));
                buffer.put(label.as_bytes());
            }
            Label::Pointer { .. } => {
                anyhow::ensure!(false);
            }
        }

        Ok(())
    }

    fn parse_value(bytes: &[u8]) -> IResult<&[u8], Label> {
        let address = bytes.as_ptr() as usize;
        let (bytes, length) = bytes::take(1usize)(bytes)?;
        assert_eq!(length.len(), 1);
        let length = length[0] as usize;
        let (bytes, label_bytes) = bytes::take(length)(bytes)?;
        let label = str::from_utf8(label_bytes).map_err(|e| Self::map_error(label_bytes, e))?;
        let label = String::from_str(label).map_err(|e| Self::map_error(label_bytes, e))?;

        Ok((bytes, Label::Value { label, address }))
    }

    fn parse_pointer(bytes: &[u8]) -> IResult<&[u8], Label> {
        let (bytes, offset) = parse_be_u16(bytes)?;
        if 0xC000 != (offset & 0xC000) {
            return nom::combinator::fail(bytes);
        } else {
            let offset = (offset & 0x3FFF) as usize;
            return Ok((bytes, Label::Pointer { offset }));
        }
    }

    fn map_error<I, E>(bytes: I, error: E) -> nom::Err<Error<I>> {
        return nom::Err::Error(Error::from_external_error(bytes, ErrorKind::Fail, error));
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Labels {
    labels: Vec<Label>,
}

impl Index<usize> for Labels {
    type Output = Label;
    fn index<'a>(&'a self, i: usize) -> &'a Label {
        return &self.labels[i];
    }
}

impl Labels {
    pub fn from_str(text: &str) -> anyhow::Result<Labels> {
        let mut labels = Vec::new();
        for label in text.split('.') {
            labels.push(Label::from_str(label)?);
        }
        Ok(Labels { labels })
    }

    pub fn parse<'a>(bytes: &'a [u8]) -> IResult<&'a [u8], Labels> {
        let mut bytes = bytes;
        let mut labels = Vec::new();
        loop {
            let (rest, label) = Label::parse(bytes)?;
            bytes = rest;
            if let Label::Value { label, .. } = &label {
                if label.len() == 0 {
                    break;
                }
            }

            labels.push(label);
        }

        Ok((bytes, Labels { labels }))
    }

    pub fn write_to(&self, buffer: &mut BytesMut) -> anyhow::Result<()> {
        for label in self.labels.iter() {
            label.write_to(buffer)?;
        }

        // The last 0-length label
        buffer.put_u8(0);

        Ok(())
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn decompress(&mut self, other: &Labels, base_offset: usize) {
        for label in self.labels.iter_mut() {
            match label {
                Label::Pointer { offset } => {
                    let target_address = base_offset + *offset;
                    let maybe_resolved = other
                        .labels
                        .iter()
                        .filter_map(|l| match l {
                            Label::Value { label, address } => {
                                if *address == target_address {
                                    Some(label)
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        })
                        .next();
                    if let Some(value) = maybe_resolved {
                        *label = Label::Value {
                            label: value.clone(),
                            address: target_address,
                        };
                    }
                }
                _ => {}
            }
        }
    }

    pub fn is_decompressed(&self) -> bool {
        self.labels.iter().all(|l| {
            if let Label::Value { .. } = l {
                true
            } else {
                false
            }
        })
    }
}

#[test]
fn test_decompression() {
    let bytes = b"\x04ABCD\x06123456\x00\x02qw\xC0\x00\xC0\x05\x00";
    let (rest, labels1) = Labels::parse(bytes).expect("Parsing should succeed");
    eprintln!("Labels1: {:?}", labels1);
    eprintln!("Rest: {:X?}", rest);
    let (rest, mut labels2) = Labels::parse(rest).expect("Parsing should succeed");

    eprintln!("Labels2: {:?}", labels2);
    eprintln!("Rest: {:X?}", rest);

    assert!(labels1.is_decompressed());
    assert!(!labels2.is_decompressed());

    labels2.decompress(&labels1, bytes.as_ptr() as usize);
    eprintln!("Labels2 after decompress: {:?}", labels2);
    assert!(labels2.is_decompressed());
}
