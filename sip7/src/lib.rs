#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use spaces_protocol::sname::{NameLike, SName, SNameRef};

const TYPE_SEQ: u8 = 0x00;
const TYPE_TXT: u8 = 0x01;
const TYPE_BLOB: u8 = 0x02;
const TYPE_SIG: u8 = 0x04;
const TYPE_ADDR: u8 = 0x05;

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
    InvalidSName,
    DuplicateSig,
    SigNotLast,
}

/// Marks the signed zone as primary
/// creates a reverse mapping for num id -> name
pub const SIG_PRIMARY_ZONE: u8 = 0x01;

/// A single record in a SIP-7 record set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Seq(u64),
    Txt {
        key: String,
        value: Vec<String>,
    },
    Blob {
        key: String,
        value: Vec<u8>,
    },
    Sig {
        flags: u8,
        canonical: SName,
        handle: SName,
        sig: Vec<u8>,
    },
    Addr {
        key: String,
        value: Vec<String>,
    },
    Unknown {
        rtype: u8,
        rdata: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigData {
    pub flags: u8,
    pub canonical: SName,
    pub handle: SName,
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signable<'a> {
    pub bytes: &'a[u8],
    pub sig: Option<SigData>,
}

impl Record {
    /// Creates a Seq record with the given version.
    pub fn seq(version: u64) -> Self {
        Record::Seq(version)
    }

    /// Creates a TXT record.
    pub fn txt(key: &str, values: &[&str]) -> Self {
        Record::Txt {
            key: String::from(key),
            value: values.iter().map(|s| String::from(*s)).collect(),
        }
    }

    /// Creates a BLOB record.
    pub fn blob(key: &str, value: Vec<u8>) -> Self {
        Record::Blob {
            key: String::from(key),
            value,
        }
    }

    /// Creates an ADDR record (same wire format as TXT, indexed for reverse lookups).
    pub fn addr(key: &str, values: &[&str]) -> Self {
        Record::Addr {
            key: String::from(key),
            value: values.iter().map(|s| String::from(*s)).collect(),
        }
    }

    /// Creates a SIG record.
    pub fn sig(canonical: SName, handle: SName, sig: Vec<u8>, flags: u8) -> Self {
        Record::Sig { flags, canonical, handle, sig }
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
                if rpos != rdata.len() {
                    return Err(Error::DataOverflow);
                }
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
            TYPE_ADDR => {
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
                Record::Addr { key, value: values }
            }
            TYPE_SIG => {
                let (sig_data, _) = parse_sig_rdata(rdata)?;
                Record::Sig {
                    flags: sig_data.flags,
                    canonical: sig_data.canonical,
                    handle: sig_data.handle,
                    sig: sig_data.sig,
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
            Record::Addr { key, value } => {
                validate_key(key)?;
                buf.push(TYPE_ADDR);
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
            Record::Sig {
                flags,
                canonical,
                handle,
                sig,
            } => {
                buf.push(TYPE_SIG);
                let canonical_bytes = canonical.to_bytes();
                let handle_bytes = handle.to_bytes();
                let data_len = 1 + canonical_bytes.len() + handle_bytes.len() + sig.len();
                write_compact_size(buf, data_len as u64);
                buf.push(*flags);
                buf.extend_from_slice(canonical_bytes);
                buf.extend_from_slice(handle_bytes);
                buf.extend_from_slice(sig);
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

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Packs a collection of records into a record set.
    ///
    /// If a `Seq` record is present it must be the first element
    /// and there must be at most one.
    pub fn pack(records: impl IntoIterator<Item = Record>) -> Result<Self, Error> {
        let records: Vec<Record> = records.into_iter().collect();
        let mut data = Vec::new();
        let mut seen_seq = false;
        let mut seen_sig = false;
        let len = records.len();
        for (index, record) in records.into_iter().enumerate() {
            if matches!(record, Record::Seq(_)) {
                if seen_seq {
                    return Err(Error::DuplicateSeq);
                }
                if index > 0 {
                    return Err(Error::SeqNotFirst);
                }
                seen_seq = true;
            }
            if matches!(record, Record::Sig { .. }) {
                if seen_sig {
                    return Err(Error::DuplicateSig);
                }
                if index != len - 1 {
                    return Err(Error::SigNotLast);
                }
                seen_sig = true;
            }
            record.pack_into(&mut data)?;
        }
        Ok(Self(data))
    }

    /// Unpacks all records as zero-copy [`ParsedRecord`] references.
    /// Performs structural validation first.
    pub fn unpack(&self) -> Result<Vec<ParsedRecord<'_>>, Error> {
        Ok(self.iter()?.iter().collect())
    }

    /// Unpacks all records as owned [`Record`] values.
    /// Malformed records become `Record::Unknown`.
    pub fn unpack_owned(&self) -> Result<Vec<Record>, Error> {
        Ok(self.iter()?.iter().map(|r| r.into()).collect())
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

    pub fn sig(&self) -> Option<SigData> {
        self.signable().sig
    }

    /// Returns the signable bytes and the SIG data if present.
    /// Signable bytes include all records plus SIG metadata
    /// (flags, canonical, handle) but exclude the raw signature.
    pub fn signable(&self) -> Signable<'_> {
        let data = self.0.as_slice();
        let mut pos = 0;

        while pos < data.len() {
            let rtype = data[pos];
            let mut rpos = pos + 1;
            let Ok(rlen) = read_compact_size(data, &mut rpos) else { break };
            let rlen = rlen as usize;
            if rpos + rlen > data.len() {
                break;
            }
            if rtype == TYPE_SIG {
                if let Ok((sig_data, sig_offset)) = parse_sig_rdata(&data[rpos..rpos + rlen]) {
                    return Signable {
                        bytes: &data[..rpos + sig_offset],
                        sig: Some(sig_data),
                    };
                }
                break;
            }
            pos = rpos + rlen;
        }

        Signable { bytes: data, sig: None }
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
            Error::InvalidSName => write!(f, "invalid space name"),
            Error::DuplicateSig => write!(f, "only one sig record is allowed"),
            Error::SigNotLast => write!(f, "sig record must be the last record"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

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
            if v < 0xFD {
                return Err(Error::DataOverflow);
            }
            *pos += 2;
            Ok(v)
        }
        0xFE => {
            if *pos + 4 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let v = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as u64;
            if v < 0x10000 {
                return Err(Error::DataOverflow);
            }
            *pos += 4;
            Ok(v)
        }
        0xFF => {
            if *pos + 8 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let v = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
            if v < 0x100000000 {
                return Err(Error::DataOverflow);
            }
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

/// Parses SIG rdata into a SigData. Returns the SigData and the byte
/// offset within rdata where the raw signature begins.
fn parse_sig_rdata(rdata: &[u8]) -> Result<(SigData, usize), Error> {
    if rdata.is_empty() {
        return Err(Error::UnexpectedEof);
    }
    let flags = rdata[0];
    let rest = &rdata[1..];
    let canonical_ref = SNameRef::try_from(rest).map_err(|_| Error::InvalidSName)?;
    let after_canonical = canonical_ref.to_bytes().len();
    let handle_ref = SNameRef::try_from(&rest[after_canonical..]).map_err(|_| Error::InvalidSName)?;
    let sig_offset = 1 + after_canonical + handle_ref.to_bytes().len();
    let sig_bytes = &rdata[sig_offset..];
    Ok((SigData {
        flags,
        canonical: canonical_ref.to_owned(),
        handle: handle_ref.to_owned(),
        sig: sig_bytes.to_vec(),
    }, sig_offset))
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

/// Zero-copy key-value parse — returns (&str, &[u8]) without allocation.
fn parse_kv_ref(data: &[u8]) -> Option<(&str, &[u8])> {
    if data.is_empty() {
        return None;
    }
    let kl = data[0] as usize;
    if kl == 0 || 1 + kl > data.len() {
        return None;
    }
    let key = core::str::from_utf8(&data[1..1 + kl]).ok()?;
    if validate_key(key).is_err() {
        return None;
    }
    Some((key, &data[1 + kl..]))
}

// ── Zero-copy parsed records ────────────────────────────────────────

/// An iterator over length-prefixed text values in wire format.
/// Yields `&str` references into the underlying byte slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextValues<'a>(&'a [u8]);

impl<'a> TextValues<'a> {
    pub fn iter(&self) -> TextValuesIter<'a> {
        TextValuesIter(self.0)
    }

    /// Collect all values into a Vec (allocating convenience).
    pub fn to_vec(&self) -> Vec<&'a str> {
        self.iter().collect()
    }
}

impl<'a> IntoIterator for &TextValues<'a> {
    type Item = &'a str;
    type IntoIter = TextValuesIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct TextValuesIter<'a>(&'a [u8]);

impl<'a> Iterator for TextValuesIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let mut pos = 0;
        let slen = read_compact_size(self.0, &mut pos).ok()? as usize;
        if pos + slen > self.0.len() {
            self.0 = &[];
            return None;
        }
        let s = core::str::from_utf8(&self.0[pos..pos + slen]).ok()?;
        self.0 = &self.0[pos + slen..];
        Some(s)
    }
}

/// A zero-copy parsed SIG record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedSig<'a> {
    pub flags: u8,
    pub canonical: SNameRef<'a>,
    pub handle: SNameRef<'a>,
    pub sig: &'a [u8],
}

/// A zero-copy parsed record. Returned from [`RecordsIter::iter`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedRecord<'a> {
    Seq(u64),
    Txt { key: &'a str, value: TextValues<'a> },
    Blob { key: &'a str, value: &'a [u8] },
    Addr { key: &'a str, value: TextValues<'a> },
    Sig(ParsedSig<'a>),
    /// Known record type but rdata could not be parsed.
    Malformed { rtype: u8, rdata: &'a [u8] },
    /// Unknown record type.
    Unknown { rtype: u8, rdata: &'a [u8] },
}

impl<'a> From<ParsedRecord<'a>> for Record {
    fn from(p: ParsedRecord<'a>) -> Self {
        match p {
            ParsedRecord::Seq(v) => Record::Seq(v),
            ParsedRecord::Txt { key, value } => Record::Txt {
                key: String::from(key),
                value: value.to_vec().into_iter().map(String::from).collect(),
            },
            ParsedRecord::Blob { key, value } => Record::Blob {
                key: String::from(key),
                value: value.to_vec(),
            },
            ParsedRecord::Addr { key, value } => Record::Addr {
                key: String::from(key),
                value: value.to_vec().into_iter().map(String::from).collect(),
            },
            ParsedRecord::Sig(sig) => Record::Sig {
                flags: sig.flags,
                canonical: sig.canonical.to_owned(),
                handle: sig.handle.to_owned(),
                sig: sig.sig.to_vec(),
            },
            ParsedRecord::Malformed { rtype, rdata } => Record::Unknown {
                rtype,
                rdata: rdata.to_vec(),
            },
            ParsedRecord::Unknown { rtype, rdata } => Record::Unknown {
                rtype,
                rdata: rdata.to_vec(),
            },
        }
    }
}

/// A structurally validated record set. Guarantees:
/// - All type/rdlength/rdata boundaries are valid
/// - At most one SEQ record, and it is first
/// - At most one SIG record, and it is last
///
/// Individual records may be `Malformed` if their rdata is invalid.
#[derive(Debug)]
pub struct RecordsIter<'a> {
    data: &'a [u8],
}

impl<'a> RecordsIter<'a> {
    pub fn iter(&self) -> ParsedRecordIter<'a> {
        ParsedRecordIter(self.data)
    }
}

impl<'a> IntoIterator for &RecordsIter<'a> {
    type Item = ParsedRecord<'a>;
    type IntoIter = ParsedRecordIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct ParsedRecordIter<'a>(&'a [u8]);

impl<'a> Iterator for ParsedRecordIter<'a> {
    type Item = ParsedRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let rtype = self.0[0];
        let mut pos = 1;
        let rlen = read_compact_size(self.0, &mut pos).ok()? as usize;
        if pos + rlen > self.0.len() {
            self.0 = &[];
            return None;
        }
        let rdata = &self.0[pos..pos + rlen];
        self.0 = &self.0[pos + rlen..];

        Some(parse_record(rtype, rdata))
    }
}

fn parse_record<'a>(rtype: u8, rdata: &'a [u8]) -> ParsedRecord<'a> {
    match rtype {
        TYPE_SEQ => {
            let mut rpos = 0;
            match read_compact_size(rdata, &mut rpos) {
                Ok(version) if rpos == rdata.len() => ParsedRecord::Seq(version),
                _ => ParsedRecord::Malformed { rtype, rdata },
            }
        }
        TYPE_TXT | TYPE_ADDR => {
            let Some((key, val_bytes)) = parse_kv_ref(rdata) else {
                return ParsedRecord::Malformed { rtype, rdata };
            };
            // Validate all values are valid UTF-8 before returning
            let values = TextValues(val_bytes);
            let mut check = TextValuesIter(val_bytes);
            let mut count = 0;
            while let Some(_) = check.next() { count += 1; }
            if !check.0.is_empty() || (count == 0 && !val_bytes.is_empty()) {
                return ParsedRecord::Malformed { rtype, rdata };
            }
            if rtype == TYPE_TXT {
                ParsedRecord::Txt { key, value: values }
            } else {
                ParsedRecord::Addr { key, value: values }
            }
        }
        TYPE_BLOB => {
            let Some((key, val_bytes)) = parse_kv_ref(rdata) else {
                return ParsedRecord::Malformed { rtype, rdata };
            };
            ParsedRecord::Blob { key, value: val_bytes }
        }
        TYPE_SIG => {
            if rdata.is_empty() {
                return ParsedRecord::Malformed { rtype, rdata };
            }
            let flags = rdata[0];
            let rest = &rdata[1..];
            let Ok(canonical) = SNameRef::try_from(rest) else {
                return ParsedRecord::Malformed { rtype, rdata };
            };
            let after_canonical = &rest[canonical.to_bytes().len()..];
            let Ok(handle) = SNameRef::try_from(after_canonical) else {
                return ParsedRecord::Malformed { rtype, rdata };
            };
            let sig = &after_canonical[handle.to_bytes().len()..];
            ParsedRecord::Sig(ParsedSig { flags, canonical, handle, sig })
        }
        _ => ParsedRecord::Unknown { rtype, rdata },
    }
}

impl RecordSet {
    /// Performs structural validation and returns a [`RecordsIter`] handle
    /// for zero-copy iteration.
    ///
    /// Validates that:
    /// - Every record has valid type + rdlength + rdata boundaries
    /// - At most one SEQ, and it is first
    /// - At most one SIG, and it is last
    ///
    /// Individual record rdata is NOT validated here — malformed rdata
    /// will produce [`ParsedRecord::Malformed`] during iteration.
    pub fn iter(&self) -> Result<RecordsIter<'_>, Error> {
        let data = self.0.as_slice();
        let mut pos = 0;
        let mut index = 0usize;
        let mut seen_seq = false;
        let mut seen_sig = false;
        let mut last_was_sig = false;

        while pos < data.len() {
            let rtype = data[pos];
            let mut rpos = pos + 1;
            let rlen = read_compact_size(data, &mut rpos)? as usize;
            if rpos + rlen > data.len() {
                return Err(Error::DataOverflow);
            }

            if last_was_sig {
                return Err(Error::SigNotLast);
            }

            if rtype == TYPE_SEQ {
                if seen_seq { return Err(Error::DuplicateSeq); }
                if index > 0 { return Err(Error::SeqNotFirst); }
                seen_seq = true;
            }

            if rtype == TYPE_SIG {
                if seen_sig { return Err(Error::DuplicateSig); }
                seen_sig = true;
                last_was_sig = true;
            }

            pos = rpos + rlen;
            index += 1;
        }

        Ok(RecordsIter { data })
    }
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
    struct SigJson {
        canonical: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        handle: Option<String>,
        sig: String,
        #[serde(default)]
        flags: u8,
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
        #[serde(rename = "sig")]
        Sig(SigJson),
        #[serde(rename = "addr")]
        Addr(TxtJson),
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
                Record::Addr { key, value } => RecordJson::Addr(TxtJson {
                    key: key.clone(),
                    value: value.clone(),
                }),
                Record::Sig {
                    flags,
                    canonical,
                    handle,
                    sig,
                } => {
                    let handle_str = if handle.is_empty() {
                        None
                    } else {
                        Some(alloc::string::ToString::to_string(handle))
                    };
                    RecordJson::Sig(SigJson {
                        canonical: alloc::string::ToString::to_string(canonical),
                        handle: handle_str,
                        sig: hex::encode(sig),
                        flags: *flags,
                    })
                }
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
                RecordJson::Txt(t) => Ok(Record::Txt {
                    key: t.key,
                    value: t.value,
                }),
                RecordJson::Addr(a) => Ok(Record::Addr {
                    key: a.key,
                    value: a.value,
                }),
                RecordJson::Blob(b) => {
                    let value = BASE64_STANDARD
                        .decode(&b.value)
                        .map_err(|_| "invalid base64 in blob value")?;
                    Ok(Record::blob(&b.key, value))
                }
                RecordJson::Sig(s) => {
                    let canonical =
                        SName::try_from(s.canonical).map_err(|_| "invalid canonical sname")?;
                    let handle = match s.handle {
                        Some(h) => SName::try_from(h).map_err(|_| "invalid handle sname")?,
                        None => SName::empty(),
                    };
                    let sig = hex::decode(&s.sig).map_err(|_| "invalid hex in sig")?;
                    Ok(Record::sig(canonical, handle, sig, s.flags))
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
            let records_iter = self.iter().map_err(serde::ser::Error::custom)?;
            let records: Vec<Record> = records_iter.iter().map(|r| r.into()).collect();
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
    use super::*;
    use alloc::vec;

    #[test]
    fn pack_unpack_seq() {
        let rs = RecordSet::pack(vec![Record::seq(1), Record::txt("btc", &["bc1qtest"])]).unwrap();

        let records = rs.unpack_owned().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], Record::Seq(1));
    }

    #[test]
    fn seq_large_version() {
        let rs = RecordSet::pack(vec![Record::seq(1000)]).unwrap();
        let records = rs.unpack_owned().unwrap();
        assert_eq!(records[0], Record::Seq(1000));
    }

    #[test]
    fn seq_u64_max() {
        let rs = RecordSet::pack(vec![Record::seq(u64::MAX)]).unwrap();
        let records = rs.unpack_owned().unwrap();
        assert_eq!(records[0], Record::Seq(u64::MAX));
    }

    #[test]
    fn seq_must_be_first_pack() {
        let err = RecordSet::pack(vec![Record::txt("btc", &["bc1q"]), Record::seq(1)]).unwrap_err();
        assert_eq!(err, Error::SeqNotFirst);
    }

    #[test]
    fn seq_must_be_first_unpack() {
        // Manually craft bytes: TXT record then SEQ record
        let mut data = Record::txt("a", &["b"]).pack().unwrap();
        data.extend_from_slice(&Record::seq(1).pack().unwrap());
        let rs = RecordSet::new(data);
        assert_eq!(rs.unpack(), Err(Error::SeqNotFirst));
    }

    #[test]
    fn duplicate_seq_pack() {
        let err = RecordSet::pack(vec![Record::seq(1), Record::seq(2)]).unwrap_err();
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
        let rs = RecordSet::pack(vec![Record::seq(42), Record::txt("btc", &["bc1q"])]).unwrap();
        assert_eq!(rs.seq(), Some(42));
    }

    #[test]
    fn no_seq_returns_none() {
        let rs = RecordSet::pack(vec![Record::txt("btc", &["bc1q"])]).unwrap();
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
            Record::txt("btc", &["bc1qtest"]),
            Record::txt("nostr", &["npub1abc"]),
        ])
        .unwrap();

        let records = rs.unpack_owned().unwrap();
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
    fn pack_unpack_addr() {
        let rs = RecordSet::pack(vec![Record::addr("btc", &["bc1qtest", "bc1qother"])]).unwrap();
        let records = rs.unpack_owned().unwrap();
        match &records[0] {
            Record::Addr { key, value } => {
                assert_eq!(key, "btc");
                assert_eq!(
                    value,
                    &vec![String::from("bc1qtest"), String::from("bc1qother")]
                );
            }
            _ => panic!("expected addr"),
        }
    }

    #[test]
    fn pack_unpack_sig() {
        use core::str::FromStr;
        let canonical = SName::from_str("@bitcoin").unwrap();
        let handle = SName::from_str("alice@bitcoin").unwrap();
        let sig_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let rs = RecordSet::pack(vec![Record::sig(
            canonical.clone(),
            handle.clone(),
            sig_bytes.clone(),
            SIG_PRIMARY_ZONE,
        )])
        .unwrap();

        let records = rs.unpack_owned().unwrap();
        match &records[0] {
            Record::Sig {
                flags,
                canonical: c,
                handle: h,
                sig,
            } => {
                assert_eq!(*flags, SIG_PRIMARY_ZONE);
                assert_eq!(c, &canonical);
                assert_eq!(h, &handle);
                assert_eq!(sig, &sig_bytes);
            }
            _ => panic!("expected sig"),
        }
    }

    #[test]
    fn pack_unpack_sig_empty_handle() {
        use core::str::FromStr;
        let canonical = SName::from_str("@bitcoin").unwrap();
        let empty_handle = SName::empty();
        let sig_bytes = vec![0x01, 0x02, 0x03];

        let rs = RecordSet::pack(vec![Record::sig(
            canonical.clone(),
            empty_handle.clone(),
            sig_bytes.clone(),
            SIG_PRIMARY_ZONE,
        )])
        .unwrap();

        let records = rs.unpack_owned().unwrap();
        match &records[0] {
            Record::Sig {
                flags,
                canonical: c,
                handle: h,
                sig,
            } => {
                assert_eq!(*flags, SIG_PRIMARY_ZONE);
                assert_eq!(c, &canonical);
                assert!(h.is_empty(), "handle should be empty");
                assert_eq!(sig, &sig_bytes);
            }
            _ => panic!("expected sig"),
        }
    }

    #[test]
    fn signable_with_sig() {
        use core::str::FromStr;
        let canonical = SName::from_str("@bitcoin").unwrap();
        let handle = SName::from_str("alice@bitcoin").unwrap();
        let sig_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let rs = RecordSet::pack(vec![
            Record::txt("btc", &["bc1qtest"]),
            Record::sig(canonical.clone(), handle.clone(), sig_bytes.clone(), 0),
        ]).unwrap();

        let signable = rs.signable();

        // signable bytes should not contain the raw signature
        assert!(!signable.bytes.is_empty());
        assert!(signable.bytes.len() < rs.as_slice().len(),
            "signable should be shorter than full record set");

        // sig data should be present
        let sig = signable.sig.expect("should have sig");
        assert_eq!(sig.flags, 0);
        assert_eq!(sig.canonical, canonical);
        assert_eq!(sig.handle, handle);
        assert_eq!(sig.sig, sig_bytes);

        // signable bytes should include TXT record + SIG header (flags, canonical, handle)
        // but not the signature itself
        let full = rs.as_slice();
        assert_eq!(&full[..signable.bytes.len()], signable.bytes,
            "signable should be a prefix of the full record set");
        assert_eq!(&full[signable.bytes.len()..], &sig_bytes,
            "remainder should be exactly the sig bytes");
    }

    #[test]
    fn signable_without_sig() {
        let rs = RecordSet::pack(vec![
            Record::txt("btc", &["bc1qtest"]),
            Record::txt("nostr", &["npub1abc"]),
        ]).unwrap();

        let signable = rs.signable();
        assert_eq!(signable.bytes, rs.as_slice(), "no SIG means signable == full record set");
        assert!(signable.sig.is_none());
    }

    #[test]
    fn sig_helper() {
        use core::str::FromStr;
        let canonical = SName::from_str("@bitcoin").unwrap();
        let handle = SName::empty();
        let sig_bytes = vec![0x01, 0x02];

        let rs = RecordSet::pack(vec![
            Record::sig(canonical.clone(), handle.clone(), sig_bytes.clone(), 0),
        ]).unwrap();

        let sig = rs.sig().expect("should have sig");
        assert_eq!(sig.canonical, canonical);
        assert!(sig.handle.is_empty());
        assert_eq!(sig.sig, sig_bytes);
    }

    #[test]
    fn sig_not_last_rejected() {
        use core::str::FromStr;
        let canonical = SName::from_str("@bitcoin").unwrap();
        let err = RecordSet::pack(vec![
            Record::sig(canonical, SName::empty(), vec![0x01], 0),
            Record::txt("btc", &["bc1q"]),
        ]).unwrap_err();
        assert_eq!(err, Error::SigNotLast);
    }

    #[test]
    fn duplicate_sig_rejected() {
        use core::str::FromStr;
        let canonical = SName::from_str("@bitcoin").unwrap();
        // First SIG isn't last, so SigNotLast fires before DuplicateSig
        let err = RecordSet::pack(vec![
            Record::sig(canonical.clone(), SName::empty(), vec![0x01], 0),
            Record::sig(canonical, SName::empty(), vec![0x02], 0),
        ]).unwrap_err();
        assert_eq!(err, Error::SigNotLast);
    }

    #[test]
    fn pack_unpack_blob() {
        let rs =
            RecordSet::pack(vec![Record::blob("avatar", vec![0x89, 0x50, 0x4E, 0x47])]).unwrap();

        let records = rs.unpack_owned().unwrap();
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

        let records = rs.unpack_owned().unwrap();
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
            Record::txt("btc", &["bc1qtest"]),
            Record::blob("data", vec![0xFF, 0x00]),
            Record::unknown(0x10, vec![0xAB]),
            Record::txt("email", &["alice@example.com"]),
        ])
        .unwrap();

        let records = rs.unpack_owned().unwrap();
        assert_eq!(records.len(), 5);
        assert_eq!(records[0], Record::Seq(1));
    }

    #[test]
    fn round_trip_type_0xff() {
        let rs = RecordSet::pack(vec![Record::unknown(0xFF, vec![1, 2, 3])]).unwrap();
        let records = rs.unpack_owned().unwrap();
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
        let record = Record::txt("btc", &["bc1qtest"]);
        let bytes = record.pack().unwrap();
        let rs = RecordSet::new(bytes);
        let records = rs.unpack_owned().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], record);
    }

    #[test]
    fn empty_record_set() {
        let rs = RecordSet::default();
        assert!(rs.is_empty());
        let records = rs.unpack_owned().unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn multi_value_txt() {
        let rs = RecordSet::pack(vec![Record::txt(
            "ns",
            &["ns1.example.com", "ns2.example.com", "ns3.example.com"],
        )])
        .unwrap();
        let records = rs.unpack_owned().unwrap();
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
        let rs = RecordSet::pack(vec![Record::txt("btc", &[""])]).unwrap();
        let records = rs.unpack_owned().unwrap();
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
        let original = RecordSet::pack(vec![Record::txt("btc", &["bc1qtest"])]).unwrap();
        let bytes = original.to_bytes();
        let restored = RecordSet::new(bytes.clone());
        assert_eq!(restored.as_slice(), &bytes);
        assert_eq!(restored.unpack_owned().unwrap().len(), 1);
    }

    #[test]
    fn lazy_iter() {
        let rs = RecordSet::pack(vec![
            Record::txt("a", &["1"]),
            Record::txt("b", &["2"]),
            Record::txt("c", &["3"]),
        ])
        .unwrap();

        let records = rs.unpack_owned().unwrap();
        assert_eq!(
            records[0],
            Record::Txt {
                key: String::from("a"),
                value: vec![String::from("1")],
            }
        );
    }

    #[test]
    fn reject_uppercase_key() {
        assert_eq!(
            Record::txt("BTC", &["bc1q"]).pack().unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn reject_invalid_key_chars() {
        assert_eq!(
            Record::txt("my_key", &["v"]).pack().unwrap_err(),
            Error::InvalidKey
        );
        assert_eq!(
            Record::txt("my.key", &["v"]).pack().unwrap_err(),
            Error::InvalidKey
        );
        assert_eq!(
            Record::txt("my key", &["v"]).pack().unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn reject_empty_key() {
        assert_eq!(
            Record::txt("", &["v"]).pack().unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn allow_valid_key_chars() {
        Record::txt("my-key-123", &["v"]).pack().unwrap();
        Record::txt("a", &["v"]).pack().unwrap();
        Record::txt("abc-def", &["v"]).pack().unwrap();
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
        let rs = RecordSet::pack(vec![Record::txt("btc", &[&long_value])]).unwrap();
        let records = rs.unpack_owned().unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn compact_size_multi_byte() {
        let long_value = "x".repeat(300);
        let rs = RecordSet::pack(vec![Record::txt("btc", &[&long_value])]).unwrap();
        assert_eq!(rs.as_slice()[1], 0xFD);
        let records = rs.unpack_owned().unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn non_minimal_compact_size_in_txt_value_is_malformed() {
        // TXT record with valid key but non-minimal compact size in value portion
        // key="btc", then value with 0xFD encoding for a small length
        let mut data = Vec::new();
        data.push(TYPE_TXT);
        let mut rdata = Vec::new();
        rdata.push(3); // key_len
        rdata.extend_from_slice(b"btc");
        // Non-minimal: value "hi" with length 2 encoded as 0xFD 0x02 0x00
        rdata.push(0xFD);
        rdata.extend_from_slice(&2u16.to_le_bytes());
        rdata.extend_from_slice(b"hi");
        write_compact_size(&mut data, rdata.len() as u64);
        data.extend_from_slice(&rdata);

        let rs = RecordSet::new(data);
        let records = rs.unpack().unwrap();
        assert_eq!(records.len(), 1);
        assert!(matches!(records[0], ParsedRecord::Malformed { rtype: TYPE_TXT, .. }));
    }

    #[test]
    fn non_minimal_compact_size_in_addr_value_is_malformed() {
        let mut data = Vec::new();
        data.push(TYPE_ADDR);
        let mut rdata = Vec::new();
        rdata.push(3);
        rdata.extend_from_slice(b"eth");
        // Non-minimal encoding for length 5
        rdata.push(0xFD);
        rdata.extend_from_slice(&5u16.to_le_bytes());
        rdata.extend_from_slice(b"0xabc");
        write_compact_size(&mut data, rdata.len() as u64);
        data.extend_from_slice(&rdata);

        let rs = RecordSet::new(data);
        let records = rs.unpack().unwrap();
        assert!(matches!(records[0], ParsedRecord::Malformed { rtype: TYPE_ADDR, .. }));
    }

    #[test]
    fn non_minimal_compact_size_in_seq_is_malformed() {
        // SEQ record where the version itself uses non-minimal encoding
        let mut data = Vec::new();
        data.push(TYPE_SEQ);
        // rdata: version 1 encoded as 0xFD 0x01 0x00 (non-minimal)
        let rdata = &[0xFD, 0x01, 0x00];
        write_compact_size(&mut data, rdata.len() as u64);
        data.extend_from_slice(rdata);

        let rs = RecordSet::new(data);
        let records = rs.unpack().unwrap();
        assert!(matches!(records[0], ParsedRecord::Malformed { rtype: TYPE_SEQ, .. }));
    }

    #[test]
    fn non_minimal_compact_size_rejected() {
        // Value 1 encoded as 0xFD 0x01 0x00 (3 bytes) instead of just 0x01 (1 byte)
        // Craft: TYPE_SEQ + non-minimal rdlength(1) + rdata(0x01)
        let data = vec![
            TYPE_SEQ,
            0xFD, 0x01, 0x00, // non-minimal: value 1 using 3-byte encoding
            0x01,              // version = 1
        ];
        let rs = RecordSet::new(data);
        assert!(rs.unpack().is_err(), "non-minimal compact size should be rejected");
        assert!(rs.iter().is_err(), "structural validation should also reject");
    }

    #[test]
    fn non_minimal_compact_size_0xfe_rejected() {
        // Value 100 encoded as 0xFE (4-byte) instead of 1-byte
        let data = vec![
            TYPE_SEQ,
            0xFE, 0x64, 0x00, 0x00, 0x00, // non-minimal: value 100 using 5-byte encoding
        ];
        let rs = RecordSet::new(data);
        assert!(rs.unpack().is_err());
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use super::*;
        use alloc::vec;

        #[test]
        fn json_round_trip_seq() {
            let rs =
                RecordSet::pack(vec![Record::seq(1), Record::txt("btc", &["bc1qtest"])]).unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            assert!(json.contains("\"type\":\"seq\""));
            assert!(json.contains("\"version\":1"));

            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack_owned().unwrap(), decoded.unpack_owned().unwrap());
        }

        #[test]
        fn json_round_trip_txt() {
            let rs = RecordSet::pack(vec![
                Record::txt("btc", &["bc1qtest"]),
                Record::txt("nostr", &["npub1abc"]),
            ])
            .unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack_owned().unwrap(), decoded.unpack_owned().unwrap());
        }

        #[test]
        fn json_round_trip_multi_value_txt() {
            let rs = RecordSet::pack(vec![Record::txt(
                "ns",
                &["ns1.example.com", "ns2.example.com"],
            )])
            .unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            assert!(json.contains(r#""value":["ns1.example.com","ns2.example.com"]"#));

            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack_owned().unwrap(), decoded.unpack_owned().unwrap());
        }

        #[test]
        fn json_round_trip_blob() {
            let rs = RecordSet::pack(vec![Record::blob("avatar", vec![0x89, 0x50, 0x4E, 0x47])])
                .unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            assert!(json.contains("\"type\":\"blob\""));
            assert!(json.contains("\"value\":\"iVBORw==\""));

            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack_owned().unwrap(), decoded.unpack_owned().unwrap());
        }

        #[test]
        fn json_round_trip_unknown() {
            let rs = RecordSet::pack(vec![Record::unknown(42, vec![1, 2, 3])]).unwrap();

            let json = serde_json::to_string(&rs).unwrap();
            assert!(json.contains("\"type\":\"unknown\""));
            assert!(json.contains("\"rtype\":42"));

            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack_owned().unwrap(), decoded.unpack_owned().unwrap());
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
            let records = rs.unpack_owned().unwrap();
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
                Record::txt("nostr", &["npub1abc"]),
                Record::txt("btc", &["bc1q..."]),
                Record::blob("some-data", b"hello".to_vec()),
            ])
            .unwrap();

            let json = serde_json::to_string_pretty(&rs).unwrap();
            let decoded: RecordSet = serde_json::from_str(&json).unwrap();
            assert_eq!(rs.unpack_owned().unwrap(), decoded.unpack_owned().unwrap());
        }

        #[test]
        fn json_seq_not_first_rejected() {
            let json = r#"[
                {"type":"txt","key":"btc","value":["bc1q..."]},
                {"type":"seq","version":1}
            ]"#;
            let err = serde_json::from_str::<RecordSet>(json);
            assert!(err.is_err());
        }
    }

    // ── Zero-copy ParsedRecord tests ────────────────────

    #[test]
    fn records_zero_copy_txt() {
        let rs = RecordSet::pack(vec![
            Record::txt("btc", &["bc1qtest", "bc1qother"]),
        ]).unwrap();

        let records = rs.iter().unwrap();
        let parsed: Vec<_> = records.iter().collect();
        assert_eq!(parsed.len(), 1);
        match &parsed[0] {
            ParsedRecord::Txt { key, value } => {
                assert_eq!(*key, "btc");
                let vals = value.to_vec();
                assert_eq!(vals, vec!["bc1qtest", "bc1qother"]);
            }
            _ => panic!("expected Txt"),
        }
    }

    #[test]
    fn records_zero_copy_addr() {
        let rs = RecordSet::pack(vec![
            Record::addr("eth", &["0xdead", "0xbeef"]),
        ]).unwrap();

        let records = rs.iter().unwrap();
        let parsed: Vec<_> = records.iter().collect();
        match &parsed[0] {
            ParsedRecord::Addr { key, value } => {
                assert_eq!(*key, "eth");
                assert_eq!(value.to_vec(), vec!["0xdead", "0xbeef"]);
            }
            _ => panic!("expected Addr"),
        }
    }

    #[test]
    fn records_zero_copy_blob() {
        let rs = RecordSet::pack(vec![
            Record::blob("avatar", vec![0x89, 0x50]),
        ]).unwrap();

        let records = rs.iter().unwrap();
        let parsed: Vec<_> = records.iter().collect();
        match &parsed[0] {
            ParsedRecord::Blob { key, value } => {
                assert_eq!(*key, "avatar");
                assert_eq!(*value, &[0x89, 0x50]);
            }
            _ => panic!("expected Blob"),
        }
    }

    #[test]
    fn records_zero_copy_sig() {
        use core::str::FromStr;
        let canonical = SName::from_str("@bitcoin").unwrap();
        let handle = SName::from_str("alice@bitcoin").unwrap();

        let rs = RecordSet::pack(vec![
            Record::txt("btc", &["bc1q"]),
            Record::sig(canonical.clone(), handle.clone(), vec![0xAB, 0xCD], 0),
        ]).unwrap();

        let records = rs.iter().unwrap();
        let parsed: Vec<_> = records.iter().collect();
        assert_eq!(parsed.len(), 2);
        match &parsed[1] {
            ParsedRecord::Sig(sig) => {
                assert_eq!(sig.flags, 0);
                assert_eq!(sig.canonical.to_owned(), canonical);
                assert_eq!(sig.handle.to_owned(), handle);
                assert_eq!(sig.sig, &[0xAB, 0xCD]);
            }
            _ => panic!("expected Sig"),
        }
    }

    #[test]
    fn records_zero_copy_seq() {
        let rs = RecordSet::pack(vec![
            Record::seq(42),
            Record::txt("a", &["b"]),
        ]).unwrap();

        let records = rs.iter().unwrap();
        let parsed: Vec<_> = records.iter().collect();
        assert_eq!(parsed.len(), 2);
        assert!(matches!(parsed[0], ParsedRecord::Seq(42)));
    }

    #[test]
    fn records_malformed_txt_becomes_malformed() {
        // Craft a TXT record with invalid UTF-8 in the value
        let mut data = Vec::new();
        data.push(TYPE_TXT);
        let rdata = &[3, b'b', b't', b'c', 2, 0xFF, 0xFE]; // key="btc", value=invalid utf8
        write_compact_size(&mut data, rdata.len() as u64);
        data.extend_from_slice(rdata);

        let rs = RecordSet::new(data);
        let records = rs.iter().unwrap(); // structural validation passes
        let parsed: Vec<_> = records.iter().collect();
        assert_eq!(parsed.len(), 1);
        assert!(matches!(parsed[0], ParsedRecord::Malformed { rtype: TYPE_TXT, .. }));
    }

    #[test]
    fn records_unknown_type() {
        let mut data = Vec::new();
        data.push(0xFF);
        write_compact_size(&mut data, 3);
        data.extend_from_slice(&[1, 2, 3]);

        let rs = RecordSet::new(data);
        let records = rs.iter().unwrap();
        let parsed: Vec<_> = records.iter().collect();
        assert!(matches!(parsed[0], ParsedRecord::Unknown { rtype: 0xFF, .. }));
    }

    #[test]
    fn records_structural_validation_rejects_sig_not_last() {
        use core::str::FromStr;
        let canonical = SName::from_str("@bitcoin").unwrap();
        // Manually craft: SIG then TXT
        let sig_bytes = Record::sig(canonical, SName::empty(), vec![0x01], 0).pack().unwrap();
        let txt_bytes = Record::txt("a", &["b"]).pack().unwrap();
        let mut data = sig_bytes;
        data.extend_from_slice(&txt_bytes);

        let rs = RecordSet::new(data);
        assert_eq!(rs.iter().unwrap_err(), Error::SigNotLast);
    }

    #[test]
    fn records_mixed_with_malformed() {
        // Good TXT + malformed TXT (bad key) + good BLOB
        let good_txt = Record::txt("btc", &["bc1q"]).pack().unwrap();
        let good_blob = Record::blob("img", vec![0x01]).pack().unwrap();

        // Craft a TXT with empty key (invalid)
        let mut bad_txt = Vec::new();
        bad_txt.push(TYPE_TXT);
        let rdata = &[0u8]; // key_len=0, no key, no value
        write_compact_size(&mut bad_txt, rdata.len() as u64);
        bad_txt.extend_from_slice(rdata);

        let mut data = good_txt;
        data.extend_from_slice(&bad_txt);
        data.extend_from_slice(&good_blob);

        let rs = RecordSet::new(data);
        let records = rs.iter().unwrap(); // structural check passes
        let parsed: Vec<_> = records.iter().collect();
        assert_eq!(parsed.len(), 3);
        assert!(matches!(parsed[0], ParsedRecord::Txt { .. }));
        assert!(matches!(parsed[1], ParsedRecord::Malformed { rtype: TYPE_TXT, .. }));
        assert!(matches!(parsed[2], ParsedRecord::Blob { .. }));
    }
}
