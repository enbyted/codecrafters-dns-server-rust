use nom::{bytes::complete as bytes, IResult};

pub fn parse_be_u16(bytes: &[u8]) -> IResult<&[u8], u16> {
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
pub fn parse_be_u32(bytes: &[u8]) -> IResult<&[u8], u32> {
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
