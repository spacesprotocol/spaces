#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::fmt;

const TYPE_TXT: u8 = 0x00;
const TYPE_BLOB: u8 = 0x01;
const TYPE_RESERVED: u8 = 0xFF;

/// A single record in a SIP-7 record set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Txt { key: String, value: String },
    Blob { key: String, value: Vec<u8> },
    Unknown { rtype: u8, rdata: Vec<u8> },
}

/// An ordered collection of SIP-7 records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSet {
    records: Vec<Record>,
}

/// Errors that can occur during record parsing or construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    ReservedType,
    UnexpectedEof,
    DataOverflow,
    EmptyData,
    KeyTooLong,
    InvalidKey,
    InvalidUtf8,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ReservedType => write!(f, "reserved type 0xFF"),
            Error::UnexpectedEof => write!(f, "unexpected end of data"),
            Error::DataOverflow => write!(f, "data length exceeds available bytes"),
            Error::EmptyData => write!(f, "empty record data"),
            Error::KeyTooLong => write!(f, "key length exceeds record data"),
            Error::InvalidKey => write!(f, "key must be lowercase ascii, digits, or hyphens"),
            Error::InvalidUtf8 => write!(f, "invalid UTF-8 in text value"),
}
    }
}

fn validate_key(key: &str) -> Result<(), Error> {
    if key.is_empty() {
        return Err(Error::InvalidKey);
    }
    if key.len() > 255 {
        return Err(Error::KeyTooLong);
    }
    if !key
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

fn read_compact_size(data: &[u8], pos: &mut usize) -> Result<usize, Error> {
    if *pos >= data.len() {
        return Err(Error::UnexpectedEof);
    }
    let first = data[*pos];
    *pos += 1;
    match first {
        0x00..=0xFC => Ok(first as usize),
        0xFD => {
            if *pos + 2 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let v = u16::from_le_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            Ok(v)
        }
        0xFE => {
            if *pos + 4 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let v = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
            *pos += 4;
            Ok(v)
        }
        0xFF => {
            if *pos + 8 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let v = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap()) as usize;
            *pos += 8;
            Ok(v)
        }
    }
}

fn write_compact_size(buf: &mut Vec<u8>, value: usize) {
    if value <= 0xFC {
        buf.push(value as u8);
    } else if value <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(value as u64).to_le_bytes());
    }
}

fn parse_kv(data: &[u8]) -> Result<(String, &[u8]), Error> {
    if data.is_empty() {
        return Err(Error::EmptyData);
    }
    let kl = data[0] as usize;
    if 1 + kl > data.len() {
        return Err(Error::KeyTooLong);
    }
    let key = core::str::from_utf8(&data[1..1 + kl]).map_err(|_| Error::InvalidKey)?;
    validate_key(key)?;
    Ok((String::from(key), &data[1 + kl..]))
}

impl Record {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Record::Txt { key, value } => {
                buf.push(TYPE_TXT);
                let data_len = 1 + key.len() + value.len();
                write_compact_size(buf, data_len);
                buf.push(key.len() as u8);
                buf.extend_from_slice(key.as_bytes());
                buf.extend_from_slice(value.as_bytes());
            }
            Record::Blob { key, value } => {
                buf.push(TYPE_BLOB);
                let data_len = 1 + key.len() + value.len();
                write_compact_size(buf, data_len);
                buf.push(key.len() as u8);
                buf.extend_from_slice(key.as_bytes());
                buf.extend_from_slice(value);
            }
            Record::Unknown { rtype, rdata } => {
                buf.push(*rtype);
                write_compact_size(buf, rdata.len());
                buf.extend_from_slice(rdata);
            }
        }
    }
}

impl RecordSet {
    /// Creates an empty record set.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Decodes a record set from its wire format.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut records = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let rtype = data[pos];
            pos += 1;

            if rtype == TYPE_RESERVED {
                return Err(Error::ReservedType);
            }

            let len = read_compact_size(data, &mut pos)?;
            if pos + len > data.len() {
                return Err(Error::DataOverflow);
            }
            let rdata = &data[pos..pos + len];
            pos += len;

            let record = match rtype {
                TYPE_TXT => {
                    let (key, val_bytes) = parse_kv(rdata)?;
                    let value =
                        core::str::from_utf8(val_bytes).map_err(|_| Error::InvalidUtf8)?;
                    Record::Txt {
                        key,
                        value: String::from(value),
                    }
                }
                TYPE_BLOB => {
                    let (key, val_bytes) = parse_kv(rdata)?;
                    Record::Blob {
                        key,
                        value: val_bytes.to_vec(),
                    }
                }
                _ => Record::Unknown {
                    rtype,
                    rdata: rdata.to_vec(),
                },
            };

            records.push(record);
        }

        Ok(Self { records })
    }

    /// Adds a TXT record.
    pub fn push_txt(&mut self, key: &str, value: &str) -> Result<(), Error> {
        validate_key(key)?;
        self.records.push(Record::Txt {
            key: String::from(key),
            value: String::from(value),
        });
        Ok(())
    }

    /// Adds a BLOB record.
    pub fn push_blob(&mut self, key: &str, value: Vec<u8>) -> Result<(), Error> {
        validate_key(key)?;
        self.records.push(Record::Blob {
            key: String::from(key),
            value,
        });
        Ok(())
    }

    /// Adds an unknown record type (preserved for round-tripping).
    pub fn push_unknown(&mut self, rtype: u8, rdata: Vec<u8>) -> Result<(), Error> {
        if rtype == TYPE_RESERVED {
            return Err(Error::ReservedType);
        }
        self.records.push(Record::Unknown { rtype, rdata });
        Ok(())
    }

    /// Encodes the record set to its wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for record in &self.records {
            record.encode(&mut buf);
        }
        buf
    }

    /// Returns a slice of all records.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Returns true if the record set contains no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }
}

impl Default for RecordSet {
    fn default() -> Self {
        Self::new()
    }
}

// --- Serde support ---

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use base64::prelude::{Engine, BASE64_STANDARD};
    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct TxtJson {
        key: String,
        value: String,
    }

    #[derive(Serialize, Deserialize)]
    struct BlobJson {
        key: String,
        value: String,
    }

    #[derive(Serialize, Deserialize)]
    struct UnknownJson {
        rtype: u8,
        rdata: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type")]
    enum RecordJson {
        #[serde(rename = "txt")]
        Txt(TxtJson),
        #[serde(rename = "blob")]
        Blob(BlobJson),
        #[serde(rename = "unknown")]
        Unknown(UnknownJson),
    }

    impl From<&Record> for RecordJson {
        fn from(r: &Record) -> Self {
            match r {
                Record::Txt { key, value } => RecordJson::Txt(TxtJson {
                    key: key.clone(),
                    value: value.clone(),
                }),
                Record::Blob { key, value } => RecordJson::Blob(BlobJson {
                    key: key.clone(),
                    value: BASE64_STANDARD.encode(value),
                }),
                Record::Unknown { rtype, rdata } => RecordJson::Unknown(UnknownJson {
                    rtype: *rtype,
                    rdata: BASE64_STANDARD.encode(rdata),
                }),
            }
        }
    }

    impl TryFrom<RecordJson> for Record {
        type Error = &'static str;

        fn try_from(j: RecordJson) -> Result<Self, Self::Error> {
            match j {
                RecordJson::Txt(t) => Ok(Record::Txt {
                    key: t.key,
                    value: t.value,
                }),
                RecordJson::Blob(b) => {
                    let value = BASE64_STANDARD
                        .decode(&b.value)
                        .map_err(|_| "invalid base64 in blob value")?;
                    Ok(Record::Blob {
                        key: b.key,
                        value,
                    })
                }
                RecordJson::Unknown(u) => {
                    let rdata = BASE64_STANDARD
                        .decode(&u.rdata)
                        .map_err(|_| "invalid base64 in unknown rdata")?;
                    Ok(Record::Unknown {
                        rtype: u.rtype,
                        rdata,
                    })
                }
            }
        }
    }

    impl Serialize for Record {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            RecordJson::from(self).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Record {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let j = RecordJson::deserialize(deserializer)?;
            Record::try_from(j).map_err(de::Error::custom)
        }
    }

    impl Serialize for RecordSet {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq = serializer.serialize_seq(Some(self.records.len()))?;
            for record in &self.records {
                seq.serialize_element(record)?;
            }
            seq.end()
        }
    }

    impl<'de> Deserialize<'de> for RecordSet {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct RecordSetVisitor;

            impl<'de> Visitor<'de> for RecordSetVisitor {
                type Value = RecordSet;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a sequence of records")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<RecordSet, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut records = Vec::new();
                    while let Some(record) = seq.next_element::<Record>()? {
                        records.push(record);
                    }
                    Ok(RecordSet { records })
                }
            }

            deserializer.deserialize_seq(RecordSetVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_txt() {
        let mut rs = RecordSet::new();
        rs.push_txt("btc", "bc1qtest").unwrap();
        rs.push_txt("nostr", "npub1abc").unwrap();

        let encoded = rs.encode();
        let decoded = RecordSet::decode(&encoded).unwrap();

        assert_eq!(rs, decoded);
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn encode_decode_blob() {
        let mut rs = RecordSet::new();
        rs.push_blob("avatar", vec![0x89, 0x50, 0x4E, 0x47]).unwrap();

        let encoded = rs.encode();
        let decoded = RecordSet::decode(&encoded).unwrap();

        assert_eq!(rs, decoded);
        match &decoded.records()[0] {
            Record::Blob { key, value } => {
                assert_eq!(key, "avatar");
                assert_eq!(value, &[0x89, 0x50, 0x4E, 0x47]);
            }
            _ => panic!("expected blob"),
        }
    }

    #[test]
    fn encode_decode_unknown() {
        let mut rs = RecordSet::new();
        rs.push_unknown(42, vec![1, 2, 3]).unwrap();

        let encoded = rs.encode();
        let decoded = RecordSet::decode(&encoded).unwrap();

        assert_eq!(rs, decoded);
        match &decoded.records()[0] {
            Record::Unknown { rtype, rdata } => {
                assert_eq!(*rtype, 42);
                assert_eq!(rdata, &[1, 2, 3]);
            }
            _ => panic!("expected unknown"),
        }
    }

    #[test]
    fn encode_decode_mixed() {
        let mut rs = RecordSet::new();
        rs.push_txt("btc", "bc1qtest").unwrap();
        rs.push_blob("data", vec![0xFF, 0x00]).unwrap();
        rs.push_unknown(0x10, vec![0xAB]).unwrap();
        rs.push_txt("email", "alice@example.com").unwrap();

        let encoded = rs.encode();
        let decoded = RecordSet::decode(&encoded).unwrap();

        assert_eq!(rs, decoded);
        assert_eq!(decoded.len(), 4);
    }

    #[test]
    fn empty_record_set() {
        let rs = RecordSet::new();
        assert!(rs.is_empty());
        let encoded = rs.encode();
        assert!(encoded.is_empty());
        let decoded = RecordSet::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn empty_txt_value() {
        let mut rs = RecordSet::new();
        rs.push_txt("btc", "").unwrap();

        let encoded = rs.encode();
        let decoded = RecordSet::decode(&encoded).unwrap();

        match &decoded.records()[0] {
            Record::Txt { key, value } => {
                assert_eq!(key, "btc");
                assert_eq!(value, "");
            }
            _ => panic!("expected txt"),
        }
    }

    #[test]
    fn reject_reserved_type() {
        let data = vec![0xFF, 0x00];
        assert_eq!(RecordSet::decode(&data), Err(Error::ReservedType));
    }

    #[test]
    fn reject_reserved_type_on_push() {
        let mut rs = RecordSet::new();
        assert_eq!(
            rs.push_unknown(0xFF, vec![]),
            Err(Error::ReservedType)
        );
    }

    #[test]
    fn reject_uppercase_key() {
        let mut rs = RecordSet::new();
        assert_eq!(rs.push_txt("BTC", "bc1q"), Err(Error::InvalidKey));
    }

    #[test]
    fn reject_invalid_key_chars() {
        let mut rs = RecordSet::new();
        assert_eq!(rs.push_txt("my_key", "val"), Err(Error::InvalidKey));
        assert_eq!(rs.push_txt("my.key", "val"), Err(Error::InvalidKey));
        assert_eq!(rs.push_txt("my key", "val"), Err(Error::InvalidKey));
    }

    #[test]
    fn reject_empty_key() {
        let mut rs = RecordSet::new();
        assert_eq!(rs.push_txt("", "val"), Err(Error::InvalidKey));
    }

    #[test]
    fn allow_valid_key_chars() {
        let mut rs = RecordSet::new();
        rs.push_txt("my-key-123", "val").unwrap();
        rs.push_txt("a", "val").unwrap();
        rs.push_txt("abc-def", "val").unwrap();
    }

    #[test]
    fn truncated_data() {
        // RType present but no length
        let data = vec![TYPE_TXT];
        assert_eq!(RecordSet::decode(&data), Err(Error::UnexpectedEof));
    }

    #[test]
    fn data_overflow() {
        // Claims 10 bytes of data but only has 3
        let data = vec![TYPE_TXT, 10, 3, b'b', b't', b'c'];
        assert_eq!(RecordSet::decode(&data), Err(Error::DataOverflow));
    }

    #[test]
    fn compact_size_boundary() {
        // Test value at 0xFC boundary (252)
        let mut rs = RecordSet::new();
        let long_value = "x".repeat(248); // key_len(1) + key(3) + value(248) = 252
        rs.push_txt("btc", &long_value).unwrap();

        let encoded = rs.encode();
        let decoded = RecordSet::decode(&encoded).unwrap();
        assert_eq!(rs, decoded);
    }

    #[test]
    fn compact_size_multi_byte() {
        // Test value requiring 0xFD prefix (> 252 bytes)
        let mut rs = RecordSet::new();
        let long_value = "x".repeat(300);
        rs.push_txt("btc", &long_value).unwrap();

        let encoded = rs.encode();
        // Verify the compact size prefix is 0xFD
        assert_eq!(encoded[1], 0xFD);
        let decoded = RecordSet::decode(&encoded).unwrap();
        assert_eq!(rs, decoded);
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use super::*;

        #[test]
        fn json_round_trip_txt() {
            let mut rs = RecordSet::new();
            rs.push_txt("btc", "bc1qtest").unwrap();
            rs.push_txt("nostr", "npub1abc").unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs, decoded);
        }

        #[test]
        fn json_round_trip_blob() {
            let mut rs = RecordSet::new();
            rs.push_blob("avatar", vec![0x89, 0x50, 0x4E, 0x47]).unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            assert!(json.contains("\"type\":\"blob\""));
            // BLOB value should be base64 encoded
            assert!(json.contains("\"value\":\"iVBORw==\""));

            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs, decoded);
        }

        #[test]
        fn json_round_trip_unknown() {
            let mut rs = RecordSet::new();
            rs.push_unknown(42, vec![1, 2, 3]).unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            assert!(json.contains("\"type\":\"unknown\""));
            assert!(json.contains("\"rtype\":42"));

            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs, decoded);
        }

        #[test]
        fn json_matches_spec_format() {
            let json = r#"[
                {"type":"txt","key":"btc","value":"bc1q..."},
                {"type":"blob","key":"some-data","value":"aGVsbG8="},
                {"type":"unknown","rtype":42,"rdata":"AQID"}
            ]"#;

            let rs: RecordSet = serde_json::from_str(json).unwrap();
            assert_eq!(rs.len(), 3);

            match &rs.records()[0] {
                Record::Txt { key, value } => {
                    assert_eq!(key, "btc");
                    assert_eq!(value, "bc1q...");
                }
                _ => panic!("expected txt"),
            }

            match &rs.records()[1] {
                Record::Blob { key, value } => {
                    assert_eq!(key, "some-data");
                    assert_eq!(value, b"hello");
                }
                _ => panic!("expected blob"),
            }

            match &rs.records()[2] {
                Record::Unknown { rtype, rdata } => {
                    assert_eq!(*rtype, 42);
                    assert_eq!(rdata, &[1, 2, 3]);
                }
                _ => panic!("expected unknown"),
            }
        }

        #[test]
        fn json_pretty_output() {
            let mut rs = RecordSet::new();
            rs.push_txt("nostr", "npub1abc").unwrap();
            rs.push_txt("btc", "bc1q...").unwrap();
            rs.push_blob("some-data", b"hello".to_vec()).unwrap();

            let json = serde_json::to_string_pretty(&rs).unwrap();
            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs, decoded);
        }
    }
}
