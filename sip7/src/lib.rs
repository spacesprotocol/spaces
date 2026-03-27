#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

const TYPE_SEQ: u8 = 0x00;
const TYPE_TXT: u8 = 0x01;
const TYPE_BLOB: u8 = 0x02;

/// Errors that can occur during record parsing or construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    UnexpectedEof,
    DataOverflow,
    EmptyData,
    KeyTooLong,
    InvalidKey,
    InvalidUtf8,
    SeqNotFirst,
    DuplicateSeq,
}

/// A single record in a SIP-7 record set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Seq(u64),
    Txt { key: String, value: Vec<String> },
    Blob { key: String, value: Vec<u8> },
    Unknown { rtype: u8, rdata: Vec<u8> },
}

impl Record {
    /// Creates a Seq record with the given version.
    pub fn seq(version: u64) -> Self {
        Record::Seq(version)
    }

    /// Creates a TXT record with a single value.
    pub fn txt(key: &str, value: &str) -> Self {
        Record::Txt {
            key: String::from(key),
            value: alloc::vec![String::from(value)],
        }
    }

    /// Creates a TXT record with multiple values.
    pub fn txts(key: &str, values: Vec<String>) -> Self {
        Record::Txt {
            key: String::from(key),
            value: values,
        }
    }

    /// Creates a BLOB record.
    pub fn blob(key: &str, value: Vec<u8>) -> Self {
        Record::Blob {
            key: String::from(key),
            value,
        }
    }

    /// Creates an unknown record type (preserved for round-tripping).
    pub fn unknown(rtype: u8, rdata: Vec<u8>) -> Self {
        Record::Unknown { rtype, rdata }
    }

    /// Packs this record into its wire-format bytes.
    /// The output is a valid single-record record set.
    pub fn pack(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        self.pack_into(&mut buf)?;
        Ok(buf)
    }

    /// Unpacks a single record from the start of a byte slice.
    /// Returns the record and the number of bytes consumed, or
    /// `Ok(None)` if the slice is empty.
    pub fn unpack(data: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        if data.is_empty() {
            return Ok(None);
        }

        let mut pos = 0;
        let rtype = data[pos];
        pos += 1;

        let len = read_compact_size(data, &mut pos)? as usize;
        if pos + len > data.len() {
            return Err(Error::DataOverflow);
        }
        let rdata = &data[pos..pos + len];
        pos += len;

        let record = match rtype {
            TYPE_SEQ => {
                let mut rpos = 0;
                let version = read_compact_size(rdata, &mut rpos)?;
                Record::Seq(version)
            }
            TYPE_TXT => {
                let (key, val_bytes) = parse_kv(rdata)?;
                let mut values = Vec::new();
                let mut vpos = 0;
                while vpos < val_bytes.len() {
                    let slen = read_compact_size(val_bytes, &mut vpos)? as usize;
                    if vpos + slen > val_bytes.len() {
                        return Err(Error::UnexpectedEof);
                    }
                    let s = core::str::from_utf8(&val_bytes[vpos..vpos + slen])
                        .map_err(|_| Error::InvalidUtf8)?;
                    values.push(String::from(s));
                    vpos += slen;
                }
                Record::Txt { key, value: values }
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

        Ok(Some((record, pos)))
    }

    fn pack_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Record::Seq(version) => {
                buf.push(TYPE_SEQ);
                let mut version_buf = Vec::new();
                write_compact_size(&mut version_buf, *version);
                write_compact_size(buf, version_buf.len() as u64);
                buf.extend_from_slice(&version_buf);
            }
            Record::Txt { key, value } => {
                validate_key(key)?;
                buf.push(TYPE_TXT);
                // Build value portion: <compact_len><text><compact_len><text>...
                let mut val_buf = Vec::new();
                for s in value {
                    write_compact_size(&mut val_buf, s.len() as u64);
                    val_buf.extend_from_slice(s.as_bytes());
                }
                let data_len = 1 + key.len() + val_buf.len();
                write_compact_size(buf, data_len as u64);
                buf.push(key.len() as u8);
                buf.extend_from_slice(key.as_bytes());
                buf.extend_from_slice(&val_buf);
            }
            Record::Blob { key, value } => {
                validate_key(key)?;
                buf.push(TYPE_BLOB);
                let data_len = 1 + key.len() + value.len();
                write_compact_size(buf, data_len as u64);
                buf.push(key.len() as u8);
                buf.extend_from_slice(key.as_bytes());
                buf.extend_from_slice(value);
            }
            Record::Unknown { rtype, rdata } => {
                buf.push(*rtype);
                write_compact_size(buf, rdata.len() as u64);
                buf.extend_from_slice(rdata);
            }
        }
        Ok(())
    }
}

/// An ordered collection of SIP-7 records in wire format.
///
/// Stores packed bytes internally. Records are only parsed on demand
/// via [`unpack`](RecordSet::unpack) or [`iter`](RecordSet::iter).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordSet(Vec<u8>);

impl RecordSet {
    /// Wraps raw wire-format bytes. No parsing is performed.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Packs a collection of records into a record set.
    ///
    /// If a `Seq` record is present it must be the first element
    /// and there must be at most one.
    pub fn pack(records: impl IntoIterator<Item = Record>) -> Result<Self, Error> {
        let mut data = Vec::new();
        let mut seen_seq = false;
        let mut index = 0usize;
        for record in records {
            if matches!(record, Record::Seq(_)) {
                if seen_seq {
                    return Err(Error::DuplicateSeq);
                }
                if index > 0 {
                    return Err(Error::SeqNotFirst);
                }
                seen_seq = true;
            }
            record.pack_into(&mut data)?;
            index += 1;
        }
        Ok(Self(data))
    }

    /// Unpacks all records, returning an error if any record is malformed.
    pub fn unpack(&self) -> Result<Vec<Record>, Error> {
        self.iter().collect()
    }

    /// Returns a lazy iterator over the records.
    pub fn iter(&self) -> RecordIter<'_> {
        RecordIter {
            data: self.0.as_slice(),
            index: 0,
            seen_seq: false,
        }
    }

    /// Returns the raw wire-format bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Consumes the record set and returns the raw bytes.
    pub fn to_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns true if the record set contains no data.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the Seq version if the first record is a Seq.
    /// Only parses the first record; does not validate the rest.
    pub fn seq(&self) -> Option<u64> {
        match Record::unpack(self.0.as_slice()) {
            Ok(Some((Record::Seq(version), _))) => Some(version),
            _ => None,
        }
    }
}

/// An iterator that lazily unpacks records from a byte slice.
pub struct RecordIter<'a> {
    data: &'a [u8],
    index: usize,
    seen_seq: bool,
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = Result<Record, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        match Record::unpack(self.data) {
            Ok(Some((record, consumed))) => {
                if matches!(record, Record::Seq(_)) {
                    if self.seen_seq {
                        self.data = &[];
                        return Some(Err(Error::DuplicateSeq));
                    }
                    if self.index > 0 {
                        self.data = &[];
                        return Some(Err(Error::SeqNotFirst));
                    }
                    self.seen_seq = true;
                }
                self.data = &self.data[consumed..];
                self.index += 1;
                Some(Ok(record))
            }
            Ok(None) => None,
            Err(e) => {
                self.data = &[];
                Some(Err(e))
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEof => write!(f, "unexpected end of data"),
            Error::DataOverflow => write!(f, "data length exceeds available bytes"),
            Error::EmptyData => write!(f, "empty record data"),
            Error::KeyTooLong => write!(f, "key length exceeds 255 bytes"),
            Error::InvalidKey => write!(f, "key must be lowercase ascii, digits, or hyphens"),
            Error::InvalidUtf8 => write!(f, "invalid UTF-8 in text value"),
            Error::SeqNotFirst => write!(f, "seq record must be the first record"),
            Error::DuplicateSeq => write!(f, "only one seq record is allowed"),
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

fn read_compact_size(data: &[u8], pos: &mut usize) -> Result<u64, Error> {
    if *pos >= data.len() {
        return Err(Error::UnexpectedEof);
    }
    let first = data[*pos];
    *pos += 1;
    match first {
        0x00..=0xFC => Ok(first as u64),
        0xFD => {
            if *pos + 2 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let v = u16::from_le_bytes([data[*pos], data[*pos + 1]]) as u64;
            *pos += 2;
            Ok(v)
        }
        0xFE => {
            if *pos + 4 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let v = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as u64;
            *pos += 4;
            Ok(v)
        }
        0xFF => {
            if *pos + 8 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let v = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            Ok(v)
        }
    }
}

fn write_compact_size(buf: &mut Vec<u8>, value: u64) {
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
        buf.extend_from_slice(&value.to_le_bytes());
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

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use base64::prelude::{Engine, BASE64_STANDARD};
    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct SeqJson {
        version: u64,
    }

    #[derive(Serialize, Deserialize)]
    struct TxtJson {
        key: String,
        value: Vec<String>,
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
        #[serde(rename = "seq")]
        Seq(SeqJson),
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
                Record::Seq(version) => RecordJson::Seq(SeqJson { version: *version }),
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
                RecordJson::Seq(s) => Ok(Record::seq(s.version)),
                RecordJson::Txt(t) => Ok(Record::txts(&t.key, t.value)),
                RecordJson::Blob(b) => {
                    let value = BASE64_STANDARD
                        .decode(&b.value)
                        .map_err(|_| "invalid base64 in blob value")?;
                    Ok(Record::blob(&b.key, value))
                }
                RecordJson::Unknown(u) => {
                    let rdata = BASE64_STANDARD
                        .decode(&u.rdata)
                        .map_err(|_| "invalid base64 in unknown rdata")?;
                    Ok(Record::unknown(u.rtype, rdata))
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
            let records: Vec<Record> = self
                .iter()
                .collect::<Result<Vec<_>, _>>()
                .map_err(serde::ser::Error::custom)?;
            let mut seq = serializer.serialize_seq(Some(records.len()))?;
            for record in &records {
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
                    Ok(RecordSet::pack(records).map_err(de::Error::custom)?)
                }
            }

            deserializer.deserialize_seq(RecordSetVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::*;

    #[test]
    fn pack_unpack_seq() {
        let rs = RecordSet::pack(vec![
            Record::seq(1),
            Record::txt("btc", "bc1qtest"),
        ]).unwrap();

        let records = rs.unpack().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], Record::Seq(1));
    }

    #[test]
    fn seq_large_version() {
        let rs = RecordSet::pack(vec![Record::seq(1000)]).unwrap();
        let records = rs.unpack().unwrap();
        assert_eq!(records[0], Record::Seq(1000));
    }

    #[test]
    fn seq_u64_max() {
        let rs = RecordSet::pack(vec![Record::seq(u64::MAX)]).unwrap();
        let records = rs.unpack().unwrap();
        assert_eq!(records[0], Record::Seq(u64::MAX));
    }

    #[test]
    fn seq_must_be_first_pack() {
        let err = RecordSet::pack(vec![
            Record::txt("btc", "bc1q"),
            Record::seq(1),
        ]).unwrap_err();
        assert_eq!(err, Error::SeqNotFirst);
    }

    #[test]
    fn seq_must_be_first_unpack() {
        // Manually craft bytes: TXT record then SEQ record
        let mut data = Record::txt("a", "b").pack().unwrap();
        data.extend_from_slice(&Record::seq(1).pack().unwrap());
        let rs = RecordSet::new(data);
        assert_eq!(rs.unpack(), Err(Error::SeqNotFirst));
    }

    #[test]
    fn duplicate_seq_pack() {
        let err = RecordSet::pack(vec![
            Record::seq(1),
            Record::seq(2),
        ]).unwrap_err();
        assert_eq!(err, Error::DuplicateSeq);
    }

    #[test]
    fn duplicate_seq_unpack() {
        // Manually craft bytes: two SEQ records
        let mut data = Record::seq(1).pack().unwrap();
        data.extend_from_slice(&Record::seq(2).pack().unwrap());
        let rs = RecordSet::new(data);
        assert_eq!(rs.unpack(), Err(Error::DuplicateSeq));
    }

    #[test]
    fn seq_helper_returns_version() {
        let rs = RecordSet::pack(vec![
            Record::seq(42),
            Record::txt("btc", "bc1q"),
        ]).unwrap();
        assert_eq!(rs.seq(), Some(42));
    }

    #[test]
    fn no_seq_returns_none() {
        let rs = RecordSet::pack(vec![
            Record::txt("btc", "bc1q"),
        ]).unwrap();
        assert_eq!(rs.seq(), None);
    }

    #[test]
    fn empty_set_seq_returns_none() {
        let rs = RecordSet::default();
        assert_eq!(rs.seq(), None);
    }

    #[test]
    fn pack_unpack_txt() {
        let rs = RecordSet::pack(vec![
            Record::txt("btc", "bc1qtest"),
            Record::txt("nostr", "npub1abc"),
        ]).unwrap();

        let records = rs.unpack().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0],
            Record::Txt {
                key: String::from("btc"),
                value: vec![String::from("bc1qtest")],
            }
        );
    }

    #[test]
    fn pack_unpack_blob() {
        let rs = RecordSet::pack(vec![
            Record::blob("avatar", vec![0x89, 0x50, 0x4E, 0x47]),
        ]).unwrap();

        let records = rs.unpack().unwrap();
        match &records[0] {
            Record::Blob { key, value } => {
                assert_eq!(key, "avatar");
                assert_eq!(value, &[0x89, 0x50, 0x4E, 0x47]);
            }
            _ => panic!("expected blob"),
        }
    }

    #[test]
    fn pack_unpack_unknown() {
        let rs = RecordSet::pack(vec![Record::unknown(42, vec![1, 2, 3])]).unwrap();

        let records = rs.unpack().unwrap();
        match &records[0] {
            Record::Unknown { rtype, rdata } => {
                assert_eq!(*rtype, 42);
                assert_eq!(rdata, &[1, 2, 3]);
            }
            _ => panic!("expected unknown"),
        }
    }

    #[test]
    fn pack_unpack_mixed() {
        let rs = RecordSet::pack(vec![
            Record::seq(1),
            Record::txt("btc", "bc1qtest"),
            Record::blob("data", vec![0xFF, 0x00]),
            Record::unknown(0x10, vec![0xAB]),
            Record::txt("email", "alice@example.com"),
        ]).unwrap();

        let records = rs.unpack().unwrap();
        assert_eq!(records.len(), 5);
        assert_eq!(records[0], Record::Seq(1));
    }

    #[test]
    fn round_trip_type_0xff() {
        let rs = RecordSet::pack(vec![Record::unknown(0xFF, vec![1, 2, 3])]).unwrap();
        let records = rs.unpack().unwrap();
        assert_eq!(records.len(), 1);
        match &records[0] {
            Record::Unknown { rtype, rdata } => {
                assert_eq!(*rtype, 0xFF);
                assert_eq!(rdata, &[1, 2, 3]);
            }
            _ => panic!("expected unknown"),
        }
    }

    #[test]
    fn single_record_pack_is_valid_record_set() {
        let record = Record::txt("btc", "bc1qtest");
        let bytes = record.pack().unwrap();
        let rs = RecordSet::new(bytes);
        let records = rs.unpack().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], record);
    }

    #[test]
    fn empty_record_set() {
        let rs = RecordSet::default();
        assert!(rs.is_empty());
        let records = rs.unpack().unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn multi_value_txt() {
        let rs = RecordSet::pack(vec![
            Record::txts("ns", vec![
                String::from("ns1.example.com"),
                String::from("ns2.example.com"),
                String::from("ns3.example.com"),
            ]),
        ]).unwrap();
        let records = rs.unpack().unwrap();
        match &records[0] {
            Record::Txt { key, value } => {
                assert_eq!(key, "ns");
                assert_eq!(value.len(), 3);
                assert_eq!(value[0], "ns1.example.com");
                assert_eq!(value[1], "ns2.example.com");
                assert_eq!(value[2], "ns3.example.com");
            }
            _ => panic!("expected txt"),
        }
    }

    #[test]
    fn empty_txt_value() {
        let rs = RecordSet::pack(vec![Record::txt("btc", "")]).unwrap();
        let records = rs.unpack().unwrap();
        match &records[0] {
            Record::Txt { key, value } => {
                assert_eq!(key, "btc");
                assert_eq!(value, &vec![String::from("")]);
            }
            _ => panic!("expected txt"),
        }
    }

    #[test]
    fn new_wraps_raw_bytes() {
        let original = RecordSet::pack(vec![Record::txt("btc", "bc1qtest")]).unwrap();
        let bytes = original.to_bytes();
        let restored = RecordSet::new(bytes.clone());
        assert_eq!(restored.as_slice(), &bytes);
        assert_eq!(restored.unpack().unwrap().len(), 1);
    }

    #[test]
    fn lazy_iter() {
        let rs = RecordSet::pack(vec![
            Record::txt("a", "1"),
            Record::txt("b", "2"),
            Record::txt("c", "3"),
        ]).unwrap();

        let first = rs.iter().next().unwrap().unwrap();
        assert_eq!(
            first,
            Record::Txt {
                key: String::from("a"),
                value: vec![String::from("1")],
            }
        );
    }

    #[test]
    fn reject_uppercase_key() {
        assert_eq!(Record::txt("BTC", "bc1q").pack().unwrap_err(), Error::InvalidKey);
    }

    #[test]
    fn reject_invalid_key_chars() {
        assert_eq!(Record::txt("my_key", "v").pack().unwrap_err(), Error::InvalidKey);
        assert_eq!(Record::txt("my.key", "v").pack().unwrap_err(), Error::InvalidKey);
        assert_eq!(Record::txt("my key", "v").pack().unwrap_err(), Error::InvalidKey);
    }

    #[test]
    fn reject_empty_key() {
        assert_eq!(Record::txt("", "v").pack().unwrap_err(), Error::InvalidKey);
    }

    #[test]
    fn allow_valid_key_chars() {
        Record::txt("my-key-123", "v").pack().unwrap();
        Record::txt("a", "v").pack().unwrap();
        Record::txt("abc-def", "v").pack().unwrap();
    }

    #[test]
    fn pack_rejects_invalid_key() {
        let bad = Record::Txt {
            key: String::from("INVALID"),
            value: vec![String::from("v")],
        };
        assert_eq!(bad.pack().unwrap_err(), Error::InvalidKey);
    }

    #[test]
    fn recordset_pack_rejects_invalid_key() {
        let bad = Record::Txt {
            key: String::from("BAD_KEY"),
            value: vec![String::from("v")],
        };
        assert_eq!(RecordSet::pack(vec![bad]).unwrap_err(), Error::InvalidKey);
    }

    #[test]
    fn truncated_data() {
        let rs = RecordSet::new(vec![TYPE_TXT]);
        assert_eq!(rs.unpack(), Err(Error::UnexpectedEof));
    }

    #[test]
    fn data_overflow() {
        let rs = RecordSet::new(vec![TYPE_TXT, 10, 3, b'b', b't', b'c']);
        assert_eq!(rs.unpack(), Err(Error::DataOverflow));
    }

    #[test]
    fn compact_size_boundary() {
        let long_value = "x".repeat(248);
        let rs = RecordSet::pack(vec![Record::txt("btc", &long_value)]).unwrap();
        let records = rs.unpack().unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn compact_size_multi_byte() {
        let long_value = "x".repeat(300);
        let rs = RecordSet::pack(vec![Record::txt("btc", &long_value)]).unwrap();
        assert_eq!(rs.as_slice()[1], 0xFD);
        let records = rs.unpack().unwrap();
        assert_eq!(records.len(), 1);
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use alloc::vec;
        use super::*;

        #[test]
        fn json_round_trip_seq() {
            let rs = RecordSet::pack(vec![
                Record::seq(1),
                Record::txt("btc", "bc1qtest"),
            ]).unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            assert!(json.contains("\"type\":\"seq\""));
            assert!(json.contains("\"version\":1"));

            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack().unwrap(), decoded.unpack().unwrap());
        }

        #[test]
        fn json_round_trip_txt() {
            let rs = RecordSet::pack(vec![
                Record::txt("btc", "bc1qtest"),
                Record::txt("nostr", "npub1abc"),
            ]).unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack().unwrap(), decoded.unpack().unwrap());
        }

        #[test]
        fn json_round_trip_multi_value_txt() {
            let rs = RecordSet::pack(vec![
                Record::txts("ns", vec![
                    String::from("ns1.example.com"),
                    String::from("ns2.example.com"),
                ]),
            ]).unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            assert!(json.contains(r#""value":["ns1.example.com","ns2.example.com"]"#));

            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack().unwrap(), decoded.unpack().unwrap());
        }

        #[test]
        fn json_round_trip_blob() {
            let rs = RecordSet::pack(vec![
                Record::blob("avatar", vec![0x89, 0x50, 0x4E, 0x47]),
            ]).unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            assert!(json.contains("\"type\":\"blob\""));
            assert!(json.contains("\"value\":\"iVBORw==\""));

            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack().unwrap(), decoded.unpack().unwrap());
        }

        #[test]
        fn json_round_trip_unknown() {
            let rs = RecordSet::pack(vec![Record::unknown(42, vec![1, 2, 3])]).unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            assert!(json.contains("\"type\":\"unknown\""));
            assert!(json.contains("\"rtype\":42"));

            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack().unwrap(), decoded.unpack().unwrap());
        }

        #[test]
        fn json_matches_spec_format() {
            let json = r#"[
                {"type":"seq","version":1},
                {"type":"txt","key":"btc","value":["bc1q..."]},
                {"type":"blob","key":"some-data","value":"aGVsbG8="},
                {"type":"unknown","rtype":42,"rdata":"AQID"}
            ]"#;

            let rs: RecordSet = serde_json::from_str(json).unwrap();
            let records = rs.unpack().unwrap();
            assert_eq!(records.len(), 4);
            assert_eq!(records[0], Record::Seq(1));

            match &records[1] {
                Record::Txt { key, value } => {
                    assert_eq!(key, "btc");
                    assert_eq!(value, &vec![String::from("bc1q...")]);
                }
                _ => panic!("expected txt"),
            }

            match &records[2] {
                Record::Blob { key, value } => {
                    assert_eq!(key, "some-data");
                    assert_eq!(value, b"hello");
                }
                _ => panic!("expected blob"),
            }

            match &records[3] {
                Record::Unknown { rtype, rdata } => {
                    assert_eq!(*rtype, 42);
                    assert_eq!(rdata, &[1, 2, 3]);
                }
                _ => panic!("expected unknown"),
            }
        }

        #[test]
        fn json_pretty_output() {
            let rs = RecordSet::pack(vec![
                Record::txt("nostr", "npub1abc"),
                Record::txt("btc", "bc1q..."),
                Record::blob("some-data", b"hello".to_vec()),
            ]).unwrap();

            let json = serde_json::to_string_pretty(&rs).unwrap();
            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack().unwrap(), decoded.unpack().unwrap());
        }

        #[test]
        fn json_seq_not_first_rejected() {
            let json = r#"[
                {"type":"txt","key":"btc","value":"bc1q..."},
                {"type":"seq","version":1}
            ]"#;
            let err = serde_json::from_str::<RecordSet>(json);
            assert!(err.is_err());
        }
    }
}
