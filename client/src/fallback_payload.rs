use std::io::{self, Read};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use clap::Args;
use sip7::RecordSet;

/// Shared CLI flags for composing SIP-7 fallback payload bytes.
#[derive(Args, Debug, Default, Clone)]
pub struct FallbackDataFlags {
    /// Add a TXT record (key=value, can be repeated)
    #[arg(long = "txt", value_name = "KEY=VALUE")]
    pub txt_records: Vec<String>,
    /// Add an ADDR record (key=addr[,addr...], can be repeated)
    #[arg(long = "addr", value_name = "KEY=VALUE[,VALUE...]")]
    pub addr_records: Vec<String>,
    /// Add a BLOB record (key=base64, can be repeated)
    #[arg(long = "blob", value_name = "KEY=BASE64")]
    pub blob_records: Vec<String>,
    /// Set raw wire-format data as base64
    #[arg(
        long,
        conflicts_with_all = ["txt_records", "addr_records", "blob_records", "stdin"]
    )]
    pub raw: Option<String>,
    /// Read JSON records from stdin
    #[arg(
        long,
        conflicts_with_all = ["txt_records", "addr_records", "blob_records", "raw"]
    )]
    pub stdin: bool,
}

impl FallbackDataFlags {
    pub fn into_input(self) -> FallbackPayloadInput {
        FallbackPayloadInput {
            txt_records: self.txt_records,
            blob_records: self.blob_records,
            addr_records: self.addr_records,
            raw: self.raw,
            stdin: self.stdin,
        }
    }

    /// Returns `None` when no fallback flags were provided.
    pub fn optional_payload(self) -> Result<Option<Vec<u8>>> {
        let input = self.into_input();
        if !input.has_input() {
            return Ok(None);
        }
        build_fallback_payload(&input).map(Some)
    }

    /// Requires at least one fallback input flag.
    pub fn required_payload(self) -> Result<Vec<u8>> {
        build_fallback_payload(&self.into_input())
    }
}

/// CLI / RPC inputs for building a SIP-7 fallback payload (`OP_RETURN` data).
#[derive(Debug, Default, Clone)]
pub struct FallbackPayloadInput {
    pub txt_records: Vec<String>,
    pub blob_records: Vec<String>,
    pub addr_records: Vec<String>,
    pub raw: Option<String>,
    pub stdin: bool,
}

impl FallbackPayloadInput {
    pub fn has_input(&self) -> bool {
        self.stdin
            || self.raw.is_some()
            || !self.txt_records.is_empty()
            || !self.blob_records.is_empty()
            || !self.addr_records.is_empty()
    }
}

/// Build SIP-7 record-set bytes from CLI-style inputs (same encoding as `setfallback`).
pub fn build_fallback_payload(input: &FallbackPayloadInput) -> Result<Vec<u8>> {
    if let Some(raw_b64) = &input.raw {
        return base64::engine::general_purpose::STANDARD
            .decode(raw_b64)
            .map_err(|e| anyhow!("Could not base64 decode data: {}", e));
    }

    if input.stdin {
        let mut data = String::new();
        io::stdin()
            .read_to_string(&mut data)
            .context("Failed to read stdin")?;
        let record_set: RecordSet = serde_json::from_str(data.trim())
            .map_err(|e| anyhow!("Invalid SIP-7 JSON: {}", e))?;
        return Ok(record_set.to_bytes());
    }

    if !input.txt_records.is_empty()
        || !input.blob_records.is_empty()
        || !input.addr_records.is_empty()
    {
        let mut records = Vec::new();
        for txt in &input.txt_records {
            let (key, value) = txt
                .split_once('=')
                .ok_or_else(|| anyhow!("Invalid --txt format '{}': expected key=value", txt))?;
            records.push(sip7::Record::txt(key, &[value]));
        }
        for blob in &input.blob_records {
            let (key, b64_value) = blob
                .split_once('=')
                .ok_or_else(|| anyhow!("Invalid --blob format '{}': expected key=base64", blob))?;
            let value = base64::engine::general_purpose::STANDARD
                .decode(b64_value)
                .map_err(|e| anyhow!("Invalid base64 in --blob '{}': {}", key, e))?;
            records.push(sip7::Record::blob(key, value));
        }
        for addr in &input.addr_records {
            let (key, values) = addr
                .split_once('=')
                .ok_or_else(|| anyhow!("Invalid --addr format '{}': expected key=value", addr))?;
            let parsed: Vec<&str> = values.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
            if parsed.is_empty() {
                return Err(anyhow!(
                    "Invalid --addr format '{}': expected at least one address",
                    addr
                ));
            }
            records.push(sip7::Record::addr(key, &parsed));
        }
        return RecordSet::pack(records)
            .map_err(|e| anyhow!("Invalid record: {}", e))
            .map(|rs| rs.to_bytes());
    }

    Err(anyhow!(
        "No data specified. Use --txt, --addr, --blob, --raw, or --stdin"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_from_txt_record() {
        let input = FallbackPayloadInput {
            txt_records: vec!["btc=bc1qtest".to_string()],
            ..Default::default()
        };
        let bytes = build_fallback_payload(&input).unwrap();
        let rs = RecordSet::new(bytes);
        assert!(rs.unpack().is_ok());
    }

    #[test]
    fn builds_from_addr_record() {
        let input = FallbackPayloadInput {
            addr_records: vec!["btc=bc1qtest,bc1qother".to_string()],
            ..Default::default()
        };
        let bytes = build_fallback_payload(&input).unwrap();
        let rs = RecordSet::new(bytes);
        assert!(rs.unpack().is_ok());
    }
}
