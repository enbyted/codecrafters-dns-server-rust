use ::bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete as bytes,
    error::{Error, ErrorKind, FromExternalError},
    IResult,
};
use std::{ops::Index, str, str::FromStr};

#[repr(transparent)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Labels {
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
        let label = str::from_utf8(label_bytes)
            .map_err(|e| nom::Err::Error(Error::from_external_error(bytes, ErrorKind::Fail, e)))?;

        Ok((bytes, label))
    }
}
