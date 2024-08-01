use crate::tun::{Handler, Metrics};
use anyhow::Result;
use nom::{
    bytes::complete::{tag, take, take_while},
    character::complete::char,
    IResult,
};
use std::{collections::HashMap, str, sync::Arc};
use tokio::sync::Mutex;

// TODO: Try to split key and value.
#[derive(Debug, PartialEq)]
pub enum RespValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<String>),
    Array(Vec<RespValue>),
}

impl RespValue {
    pub fn to_string(&self) -> String {
        match self {
            RespValue::SimpleString(s) => format!("+{}", s),
            RespValue::Error(s) => format!("-{}", s),
            RespValue::Integer(i) => format!(":{}", i),
            RespValue::BulkString(Some(s)) => format!("{}", s),
            RespValue::BulkString(None) => "$-1\r\n".to_string(),
            RespValue::Array(values) => {
                let mut s = format!("");
                for value in values {
                    s.push_str(&value.to_string());
                }
                s
            }
        }
    }
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

pub fn parse_simple_string(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = char('+')(input)?;
    let (input, s) = take_while(|c| c != b'\r')(input)?;
    let (input, _) = tag("\r\n")(input)?;
    let s = str::from_utf8(s).unwrap().to_string();
    Ok((input, RespValue::SimpleString(s)))
}

pub fn parse_error(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = char('-')(input)?;
    let (input, s) = take_while(|c| c != b'\r')(input)?;
    let (input, _) = tag("\r\n")(input)?;
    let s = str::from_utf8(s).unwrap().to_string();
    Ok((input, RespValue::Error(s)))
}

pub fn parse_integer(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = char(':')(input)?;
    let (input, s) = take_while(is_digit)(input)?;
    let (input, _) = tag("\r\n")(input)?;
    let s = str::from_utf8(s).unwrap().parse().unwrap();
    Ok((input, RespValue::Integer(s)))
}

pub fn parse_bulk_string(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = char('$')(input)?;
    let (input, length_str) = take_while(is_digit)(input)?;
    let length = str::from_utf8(length_str)
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let (input, _) = tag("\r\n")(input)?;
    let (input, data) = take(length)(input)?;
    let (input, _) = tag("\r\n")(input)?;
    let s = if data.is_empty() {
        None
    } else {
        Some(str::from_utf8(data).unwrap().to_string())
    };
    Ok((input, RespValue::BulkString(s)))
}

pub fn parse_array(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = char('*')(input)?;
    let (input, length_str) = take_while(is_digit)(input)?;
    let length = str::from_utf8(length_str)
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let (input, _) = tag("\r\n")(input)?;
    let mut values = Vec::with_capacity(length);
    let mut input = input;

    for _ in 0..length {
        let (new_input, value) = parse_resp(input)?;
        input = new_input;
        values.push(value);
    }

    Ok((input, RespValue::Array(values)))
}

// General RESP parser that chooses the correct type
pub fn parse_resp(input: &[u8]) -> IResult<&[u8], RespValue> {
    nom::branch::alt((
        parse_simple_string,
        parse_error,
        parse_integer,
        parse_bulk_string,
        parse_array,
    ))(input)
}

pub struct RespHandler {
    port: u16,
    key_map: Arc<Mutex<HashMap<u32, String>>>,
}

impl RespHandler {
    pub fn new(port: u16) -> Self {
        RespHandler {
            port,
            key_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Handler<RespValue> for RespHandler {
    async fn port(&self) -> u16 {
        self.port
    }

    async fn parse_packet(&self, buf: Vec<u8>) -> Result<RespValue> {
        let resp = parse_resp(&buf).map_err(|_| anyhow::anyhow!("Failed to parse packet"))?;
        Ok(resp.1)
    }

    async fn process(&self, input: RespValue, metrics: Option<Metrics>) -> Result<()> {
        // Return if none and unpack the metrics
        if metrics.is_none() {
            return Ok(());
        }
        // We already know that metrics is not None
        let metrics = metrics.unwrap();

        let string_key = input.to_string();
        let mut store = self.key_map.lock().await;
        if !store.contains_key(&metrics.identifier) {
            // Check if the identifier exists and save it in the store
            store.insert(metrics.identifier, string_key.clone());
        }

        if let Some(latency) = metrics.latency {
            // Print the latency and the key
            println!(
                "Key: {}, Latency: {}ms",
                store.get(&metrics.identifier).unwrap(),
                latency.as_millis(),
            );
            // clean up the store
            store.remove(&metrics.identifier);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_string() {
        let data = b"+OK\r\n";
        assert_eq!(
            parse_simple_string(data),
            Ok((&b""[..], RespValue::SimpleString("OK".to_string())))
        );
    }

    #[test]
    fn test_parse_error() {
        let data = b"-Error message\r\n";
        assert_eq!(
            parse_error(data),
            Ok((&b""[..], RespValue::Error("Error message".to_string())))
        );
    }

    #[test]
    fn test_parse_integer() {
        let data = b":12345\r\n";
        assert_eq!(
            parse_integer(data),
            Ok((&b""[..], RespValue::Integer(12345)))
        );
    }

    #[test]
    fn test_parse_bulk_string() {
        let data = b"$6\r\nfoobar\r\n";
        assert_eq!(
            parse_bulk_string(data),
            Ok((&b""[..], RespValue::BulkString(Some("foobar".to_string()))))
        );
    }

    #[test]
    fn test_parse_array() {
        let data = b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
        let expected = RespValue::Array(vec![
            RespValue::BulkString(Some("foo".to_string())),
            RespValue::BulkString(Some("bar".to_string())),
        ]);
        assert_eq!(parse_array(data), Ok((&b""[..], expected)));
    }

    #[test]
    fn test_parse_resp() {
        let data = b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
        let expected = RespValue::Array(vec![
            RespValue::BulkString(Some("foo".to_string())),
            RespValue::BulkString(Some("bar".to_string())),
        ]);
        assert_eq!(parse_resp(data), Ok((&b""[..], expected)));
    }
}
