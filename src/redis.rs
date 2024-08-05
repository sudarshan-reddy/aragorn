use anyhow::Result;
use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_while},
    character::complete::char,
    IResult,
};
use std::{collections::HashMap, str, sync::Arc};
use tokio::sync::Mutex;

use crate::tun::{Handler, Metrics};

#[derive(Debug, Clone, PartialEq)]
pub struct RespValue {
    pub command: Option<String>,
    pub key: Option<String>,
    pub value: Option<String>,
}

impl RespValue {
    pub fn to_string(&self) -> String {
        let mut s = String::new();
        if let Some(ref command) = self.command {
            s.push_str(&format!("Command: {}\n", command));
        }
        if let Some(ref key) = self.key {
            s.push_str(&format!("Key: {}\n", key));
        }
        if let Some(ref value) = self.value {
            s.push_str(&format!("Value: {}\n", value));
        }
        s
    }
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn parse_simple_string(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = char('+')(input)?;
    let (input, s) = take_while(|c| c != b'\r')(input)?;
    let (input, _) = tag("\r\n")(input)?;
    let command = str::from_utf8(s).unwrap().to_string();
    Ok((
        input,
        RespValue {
            command: Some(command),
            key: None,
            value: None,
        },
    ))
}

fn parse_error(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = char('-')(input)?;
    let (input, s) = take_while(|c| c != b'\r')(input)?;
    let (input, _) = tag("\r\n")(input)?;
    let command = str::from_utf8(s).unwrap().to_string();
    Ok((
        input,
        RespValue {
            command: Some(command),
            key: None,
            value: None,
        },
    ))
}

fn parse_integer(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = char(':')(input)?;
    let (input, s) = take_while(is_digit)(input)?;
    let (input, _) = tag("\r\n")(input)?;
    let value = str::from_utf8(s).unwrap().to_string();
    Ok((
        input,
        RespValue {
            command: None,
            key: None,
            value: Some(value),
        },
    ))
}

fn parse_bulk_string(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = char('$')(input)?;
    let (input, length_str) = take_while(is_digit)(input)?;
    let length = str::from_utf8(length_str)
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let (input, _) = tag("\r\n")(input)?;
    let (input, data) = take(length)(input)?;
    let (input, _) = tag("\r\n")(input)?;
    let value = if data.is_empty() {
        None
    } else {
        Some(str::from_utf8(data).unwrap().to_string())
    };

    Ok((
        input,
        RespValue {
            command: None,
            key: None,
            value,
        },
    ))
}

fn parse_array(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = char('*')(input)?;
    let (input, length_str) = take_while(is_digit)(input)?;
    let length = str::from_utf8(length_str)
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let (input, _) = tag("\r\n")(input)?;
    let mut input = input;

    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        let (new_input, value) = parse_resp(input)?;
        input = new_input;
        values.push(value);
    }

    let command = values.get(0).and_then(|v| v.value.clone());
    let key = values.get(1).and_then(|v| v.value.clone());
    let value = values.get(2).and_then(|v| v.value.clone());

    Ok((
        input,
        RespValue {
            command,
            key,
            value,
        },
    ))
}

// General RESP parser that chooses the correct type
pub fn parse_resp(input: &[u8]) -> IResult<&[u8], RespValue> {
    alt((
        parse_simple_string,
        parse_error,
        parse_integer,
        parse_bulk_string,
        parse_array,
    ))(input)
}

// Unit Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_string() {
        let input = b"+OK\r\n";
        let expected = RespValue {
            command: Some("OK".to_string()),
            key: None,
            value: None,
        };
        assert_eq!(parse_simple_string(input).unwrap().1, expected);
    }

    #[test]
    fn test_parse_error() {
        let input = b"-Error message\r\n";
        let expected = RespValue {
            command: Some("Error message".to_string()),
            key: None,
            value: None,
        };
        assert_eq!(parse_error(input).unwrap().1, expected);
    }

    #[test]
    fn test_parse_integer() {
        let input = b":1000\r\n";
        let expected = RespValue {
            command: None,
            key: None,
            value: Some("1000".to_string()),
        };
        assert_eq!(parse_integer(input).unwrap().1, expected);
    }

    #[test]
    fn test_parse_bulk_string() {
        let input = b"$6\r\nfoobar\r\n";
        let expected = RespValue {
            command: None,
            key: None,
            value: Some("foobar".to_string()),
        };
        assert_eq!(parse_bulk_string(input).unwrap().1, expected);
    }

    #[test]
    fn test_parse_bulk_string_none() {
        let input = b"$0\r\n\r\n";
        let expected = RespValue {
            command: None,
            key: None,
            value: None,
        };
        assert_eq!(parse_bulk_string(input).unwrap().1, expected);
    }

    #[test]
    fn test_parse_array() {
        let input = b"*3\r\n$4\r\nECHO\r\n$3\r\nkey\r\n$5\r\nvalue\r\n";
        let expected = RespValue {
            command: Some("ECHO".to_string()),
            key: Some("key".to_string()),
            value: Some("value".to_string()),
        };
        assert_eq!(parse_array(input).unwrap().1, expected);
    }

    //#[test]
    //fn test_parse_array_mixed() {
    //    let input = b"*4\r\n$4\r\nECHO\r\n$3\r\nkey\r\n$5\r\nvalue\r\n$4\r\nTEST\r\n";
    //    let expected = RespValue {
    //        command: Some("ECHO".to_string()),
    //        key: Some("key".to_string()),
    //        value: Some("value".to_string()),
    //    };
    //    assert_eq!(parse_array(input).unwrap().1, expected);
    //}
}

pub struct RespHandler {
    port: u16,
    key_map: Arc<Mutex<HashMap<u32, RespValue>>>,
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

        let mut store = self.key_map.lock().await;
        if !store.contains_key(&metrics.identifier) {
            // Check if the identifier exists and save it in the store
            store.insert(metrics.identifier, input.clone());
        }

        if let Some(latency) = metrics.latency {
            let status = if input.to_string().contains("ERR") {
                "ERR"
            } else {
                "OK"
            };
            // Print the latency and the key
            let stored_value = store
                .get(&metrics.identifier)
                .ok_or_else(|| anyhow::anyhow!("Failed to get value from store"))?;
            println!(
                "Key: {}, Latency: {}ms, Status: {}",
                stored_value.key.as_ref().unwrap(),
                latency.as_millis(),
                status,
            );
            // clean up the store
            store.remove(&metrics.identifier);
        }

        Ok(())
    }
}
