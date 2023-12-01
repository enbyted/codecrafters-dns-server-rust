use bytes::BytesMut;
use nom::IResult;

use crate::{
    answer::Answer,
    header::{Header, Opcode, ResponseCode},
    query::Query,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Request {
    header: Header,
    queries: Vec<Query>,
    answers: Vec<Answer>,
}

impl Request {
    pub fn new(packet_id: u16, opcode: Opcode) -> Request {
        Request {
            header: Header {
                packet_id,
                is_reply: false,
                opcode,
                is_authoritative: false,
                truncation: false,
                recursion_desired: true,
                recursion_available: false,
                response_code: crate::header::ResponseCode::NoError,
                question_count: 0,
                answer_record_count: 0,
                authority_record_count: 0,
                additional_record_count: 0,
            },
            queries: Vec::new(),
            answers: Vec::new(),
        }
    }

    pub fn reply(request: &Request, response_code: ResponseCode) -> Request {
        Request {
            header: Header::reply(&request.header, response_code),
            queries: request.queries.clone(),
            answers: Vec::new(),
        }
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Request> {
        let base_offset = bytes.as_ptr() as usize;
        let (bytes, header) = Header::parse(bytes)?;
        let mut queries = Vec::new();
        let mut answers = Vec::new();

        if header.additional_record_count != 0 {
            return nom::combinator::fail(bytes);
        }

        if header.authority_record_count != 0 {
            return nom::combinator::fail(bytes);
        }

        let mut bytes = bytes;
        for _ in 0..header.question_count {
            let (rest, query) = Query::parse(bytes)?;
            bytes = rest;
            queries.push(query);
        }
        for _ in 0..header.answer_record_count {
            let (rest, answer) = Answer::parse(bytes)?;
            bytes = rest;
            answers.push(answer);
        }

        for i in 1..queries.len() {
            let (left, right) = queries.split_at_mut(i);
            for a in left.iter_mut() {
                for b in right.iter_mut() {
                    a.labels.decompress(&b.labels, base_offset);
                    b.labels.decompress(&a.labels, base_offset);
                }
            }
        }
        if !queries.iter().all(|q| q.labels.is_decompressed()) {
            return nom::combinator::fail(bytes);
        }

        Ok((
            bytes,
            Request {
                header,
                queries,
                answers,
            },
        ))
    }

    pub fn write_to(&self, buffer: &mut BytesMut) -> anyhow::Result<()> {
        let mut header = self.header.clone();
        header.answer_record_count = u16::try_from(self.answers.len())?;
        header.question_count = u16::try_from(self.queries.len())?;
        header.write_to(buffer);
        for query in self.queries.iter() {
            query.write_to(buffer)?;
        }
        for answer in self.answers.iter() {
            answer.write_to(buffer)?;
        }

        Ok(())
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    pub fn queries_iter(&self) -> impl Iterator<Item = &Query> {
        self.queries.iter()
    }

    pub fn answers_iter(&self) -> impl Iterator<Item = &Answer> {
        self.answers.iter()
    }

    pub fn add_answer(&mut self, answer: Answer) {
        self.answers.push(answer);
    }

    pub fn add_query(&mut self, query: Query) {
        self.queries.push(query);
    }
}

#[test]
fn test_stage5_input() {
    let data = vec![
        0x99, 0x68, 0x19, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xC, 0x63, 0x6F, 0x64, 0x65,
        0x63, 0x72, 0x61, 0x66, 0x74, 0x65, 0x72, 0x73, 0x2, 0x69, 0x6F, 0x0, 0x0, 0x1, 0x0, 0x1,
    ];
    let request = Request::parse(&data).expect("Query parse should succeed");
    eprintln!("Request: {:?}", request);
}
