use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use core::str::FromStr;
use crate::slabel::{SLabel, SLabelRef};

pub const MAX_SPACE_LEN: usize = 255;
pub const MAX_LABEL_LEN: usize = 62;

/// A DNS-encoded name representing a space handle.
///
/// Wire format: length-prefixed labels terminated by a null byte.
/// Display format: `labels@space` (e.g., `alice@bitcoin`, `key.wallet@bitcoin`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SName([u8; MAX_SPACE_LEN]);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subname(SLabel);

#[cfg(feature = "borsh")]
mod borsh_impl {
    use super::*;
    use borsh::{BorshDeserialize, BorshSerialize};
    use borsh::io::{Read, Write};

    impl BorshSerialize for SName {
        fn serialize<W: Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
            self.0.serialize(writer)
        }
    }

    impl BorshDeserialize for SName {
        fn deserialize_reader<R: Read>(reader: &mut R) -> borsh::io::Result<Self> {
            let bytes: [u8; MAX_SPACE_LEN] = BorshDeserialize::deserialize_reader(reader)?;
            Ok(SName(bytes))
        }
    }

    impl BorshSerialize for Subname {
        fn serialize<W: Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
            BorshSerialize::serialize(&self.0.as_ref().to_vec(), writer)
        }
    }

    impl BorshDeserialize for Subname {
        fn deserialize_reader<R: Read>(reader: &mut R) -> borsh::io::Result<Self> {
            let bytes: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            let slabel = SLabel::try_from(bytes.as_slice())
                .map_err(|e| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, alloc::format!("{}", e)))?;
            Ok(Subname(slabel))
        }
    }
}

impl Subname {
    pub fn as_slabel(&self) -> &SLabel {
        &self.0
    }
}

impl Display for Subname {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let s = self.0.to_string_unprefixed().map_err(|_| core::fmt::Error)?;
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Empty,
    TooLong,
    LabelTooLong,
    MissingNullTerminator,
    InvalidLabelLength,
    InvalidCharacter,
    Malformed,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Empty => write!(f, "name is empty"),
            Error::TooLong => write!(f, "name exceeds maximum length of {} bytes", MAX_SPACE_LEN),
            Error::LabelTooLong => write!(f, "label exceeds maximum length of {} bytes", MAX_LABEL_LEN),
            Error::MissingNullTerminator => write!(f, "missing null terminator"),
            Error::InvalidLabelLength => write!(f, "invalid label length byte"),
            Error::InvalidCharacter => write!(f, "invalid character"),
            Error::Malformed => write!(f, "malformed name structure"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SNameRef<'a>(pub &'a [u8]);

pub struct LabelIterator<'a>(&'a [u8]);

pub trait NameLike {
    fn inner_bytes(&self) -> &[u8];

    fn to_bytes(&self) -> &[u8] {
        let mut len = 0;
        for label in self.iter() {
            len += label.len() + 1;
        }
        len += 1;
        &self.inner_bytes()[..len]
    }

    #[inline(always)]
    fn is_single_label(&self) -> bool {
        self.label_count() == 1
    }

    fn label_count(&self) -> usize {
        let mut count = 0;
        let mut slice = &self.inner_bytes()[..];
        while !slice.is_empty() && slice[0] != 0 {
            slice = &slice[slice[0] as usize + 1..];
            count += 1;
        }
        count
    }

    #[inline(always)]
    fn iter(&self) -> LabelIterator<'_> {
        LabelIterator(&self.inner_bytes()[..])
    }
}

impl NameLike for SName {
    fn inner_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl NameLike for SNameRef<'_> {
    fn inner_bytes(&self) -> &[u8] {
        self.0
    }
}

impl SName {
    /// An empty SName (DNS root — just `\x00`).
    pub fn empty() -> Self {
        SName([0u8; MAX_SPACE_LEN])
    }

    pub fn is_empty(&self) -> bool {
        self.0[0] == 0
    }

    pub fn as_name_ref(&self) -> SNameRef<'_> {
        SNameRef(&self.0)
    }

    pub fn from_space(space: &SLabel) -> Self {
        let space_bytes = space.as_ref();
        let mut buf = [0u8; MAX_SPACE_LEN];
        buf[..space_bytes.len()].copy_from_slice(space_bytes);
        SName(buf)
    }

    pub fn join(label: &Subname, space: &SLabel) -> Result<Self, Error> {
        let label_bytes = label.0.as_ref();
        let space_bytes = space.as_ref();

        if label_bytes.is_empty() || space_bytes.is_empty() {
            return Err(Error::Empty);
        }
        if label_bytes.len() + space_bytes.len() + 1 > MAX_SPACE_LEN {
            return Err(Error::TooLong);
        }

        let mut buf = [0u8; MAX_SPACE_LEN];
        let mut pos = 0;
        buf[pos..pos + label_bytes.len()].copy_from_slice(label_bytes);
        pos += label_bytes.len();
        buf[pos..pos + space_bytes.len()].copy_from_slice(space_bytes);
        Ok(SName(buf))
    }

    /// Returns the top-level space label (e.g., `@bitcoin` from `alice@bitcoin`).
    pub fn space(&self) -> Option<SLabel> {
        let labels: Vec<&[u8]> = self.iter().collect();
        let last = labels.last()?;
        let s = core::str::from_utf8(last).ok()?;
        SLabel::from_str_unprefixed(s).ok()
    }

    /// Returns the subspace label (e.g., `alice` from `alice@bitcoin`).
    pub fn subspace(&self) -> Option<Subname> {
        let labels: Vec<&[u8]> = self.iter().collect();
        if labels.len() < 2 {
            return None;
        }
        let second_to_last = labels[labels.len() - 2];
        let s = core::str::from_utf8(second_to_last).ok()?;
        let slabel = SLabel::from_str_unprefixed(s).ok()?;
        Some(Subname(slabel))
    }
}

impl From<&SLabel> for SName {
    fn from(space: &SLabel) -> Self {
        SName::from_space(space)
    }
}

impl SNameRef<'_> {
    pub fn to_owned(&self) -> SName {
        let mut owned = SName([0; MAX_SPACE_LEN]);
        owned.0[..self.0.len()].copy_from_slice(self.0);
        owned
    }
}

impl Display for SName {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let labels: Vec<&str> = self
            .iter()
            .map(|label| core::str::from_utf8(label).unwrap())
            .collect();

        let last_label = labels.last().unwrap();
        let all_but_last = &labels[..labels.len() - 1];
        if last_label.starts_with('#') {
            write!(f, "{}{}", all_but_last.join("."), last_label)
        } else {
            write!(f, "{}@{}", all_but_last.join("."), last_label)
        }
    }
}

impl Display for SNameRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_owned())
    }
}

impl FromStr for SName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl TryFrom<&str> for SName {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Ok(SName::empty());
        }
        let (subspace, space) = if let Some(at_pos) = value.find('@') {
            let (sub, rest) = value.split_at(at_pos);
            let space = &rest[1..];
            if space.is_empty() || space.contains('.') {
                return Err(Error::Malformed);
            }
            (sub, space)
        } else if let Some(hash_pos) = value.find('#') {
            let (sub, space) = value.split_at(hash_pos);
            if space.len() <= 1 || space[1..].contains('#') || space.contains('.') {
                return Err(Error::Malformed);
            }
            (sub, space)
        } else {
            return Err(Error::Malformed);
        };

        let mut space_bytes = [0; MAX_SPACE_LEN];
        let mut space_len = 0;

        for label in subspace.split('.').chain(core::iter::once(space)) {
            if space_len == 0 && label.is_empty() {
                continue;
            }

            let slabel = SLabel::from_str_unprefixed(label)
                .map_err(|_| Error::InvalidCharacter)?;
            let slabel_bytes = slabel.as_ref();
            let slabel_len = slabel_bytes.len();

            if space_len + slabel_len + 1 > MAX_SPACE_LEN {
                return Err(Error::TooLong);
            }

            space_bytes[space_len..space_len + slabel_len].copy_from_slice(slabel_bytes);
            space_len += slabel_len;
        }

        space_bytes[space_len] = 0;
        Ok(SName(space_bytes))
    }
}

impl TryFrom<String> for SName {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl<const N: usize> TryFrom<&[u8; N]> for SName {
    type Error = Error;

    fn try_from(value: &[u8; N]) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&Vec<u8>> for SName {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&[u8]> for SName {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let name_ref: SNameRef = value.try_into()?;
        Ok(name_ref.to_owned())
    }
}

impl<'a> TryFrom<&'a [u8]> for SNameRef<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let mut remaining = value;
        if remaining.is_empty() {
            return Err(Error::Empty);
        }
        if remaining.len() > MAX_SPACE_LEN {
            return Err(Error::TooLong);
        }

        let mut parsed_len = 0;
        loop {
            if remaining.is_empty() {
                return Err(Error::MissingNullTerminator);
            }
            let label_len = remaining[0] as usize;
            if label_len == 0 {
                parsed_len += 1;
                break;
            }
            if label_len > MAX_LABEL_LEN {
                return Err(Error::LabelTooLong);
            }
            if label_len + 1 > remaining.len() {
                return Err(Error::InvalidLabelLength);
            }
            SLabelRef::try_from(&remaining[..label_len + 1])
                .map_err(|_| Error::InvalidCharacter)?;
            remaining = &remaining[label_len + 1..];
            parsed_len += label_len + 1;
        }

        Ok(SNameRef(&value[..parsed_len]))
    }
}

impl<'a> Iterator for LabelIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() || self.0[0] == 0 {
            return None;
        }

        let label_len = self.0[0] as usize;
        let (label, rest) = self.0.split_at(label_len + 1);
        self.0 = rest;
        Some(&label[1..])
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde::de::{Error as DeError, SeqAccess, Visitor};

    impl Serialize for SName {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                serializer.serialize_str(&alloc::string::ToString::to_string(self))
            } else {
                serializer.serialize_bytes(&self.0)
            }
        }
    }

    struct SNameVisitorBytes;

    impl<'de> Visitor<'de> for SNameVisitorBytes {
        type Value = SName;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("a byte array representing an SName")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut bytes = [0; MAX_SPACE_LEN];
            let mut index = 0;

            while let Some(byte) = seq.next_element()? {
                if index >= MAX_SPACE_LEN {
                    return Err(serde::de::Error::invalid_length(index, &self));
                }
                bytes[index] = byte;
                index += 1;
            }

            Ok(SName(bytes))
        }
    }

    impl<'de> Deserialize<'de> for SName {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let s = <String as Deserialize>::deserialize(deserializer)?;
                SName::from_str(&s).map_err(|e| serde::de::Error::custom(e))
            } else {
                deserializer.deserialize_seq(SNameVisitorBytes)
            }
        }
    }

    impl Serialize for Subname {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                serializer.serialize_str(&alloc::string::ToString::to_string(self))
            } else {
                Serialize::serialize(&self.0, serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for Subname {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let s = <String as Deserialize>::deserialize(deserializer)?;
                Subname::from_str(&s).map_err(DeError::custom)
            } else {
                let lbl: SLabel = <SLabel as Deserialize>::deserialize(deserializer)?;
                Ok(Subname(lbl))
            }
        }
    }
}

impl FromStr for Subname {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Subname(
            SLabel::from_str_unprefixed(s).map_err(|_| "invalid subspace label")?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_slice() {
        assert!(SName::try_from(b"").is_err());
        assert!(SName::try_from(b"\x00").is_ok());
        assert_eq!(SName::try_from(b"\x00").unwrap().label_count(), 0);

        assert!(SName::try_from(b"\x03bob").is_err(), "missing null byte");
        assert!(SName::try_from(b"\x03bob\x00").is_ok());
        assert_eq!(SName::try_from(b"\x03bob\x00").unwrap().label_count(), 1);

        assert!(SName::try_from(b"\x03bob\x07bitcoin\x00").is_ok());
        assert_eq!(
            SName::try_from(b"\x03bob\x07bitcoin\x00").unwrap().label_count(),
            2,
        );

        let mut max_label = vec![0x3e];
        max_label.extend_from_slice(&vec![b'a'; 62]);
        max_label.push(0x00);
        assert!(SName::try_from(&max_label).is_ok());

        let mut too_long_label = vec![0x3f];
        too_long_label.extend_from_slice(&vec![b'a'; 63]);
        too_long_label.push(0x00);
        assert!(SName::try_from(&too_long_label).is_err());

        assert!(SName::try_from(b"\x03bob\x00\x03foo").is_ok());
        assert_eq!(
            SName::try_from(b"\x03bob\x00\x03foo").unwrap().label_count(),
            1,
        );

        assert!(SName::try_from(b"\x03bob\x04foo\x00").is_err());
    }

    #[test]
    fn test_iter() {
        let space = SName::try_from(b"\x03bob\x07bitcoin\x00").unwrap();
        let mut iter = space.iter();
        assert_eq!(iter.next(), Some(b"bob" as &[u8]));
        assert_eq!(iter.next(), Some(b"bitcoin" as &[u8]));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_from_string() {
        let empty = SName::from_str("").unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.label_count(), 0);
        assert_eq!(empty, SName::empty());
        assert!(SName::from_str("bitcoin").is_err());
        assert!(SName::from_str("@").is_err());
        assert!(SName::from_str("hey..bob@bitcoin").is_err());

        assert!(SName::from_str("@bitcoin").is_ok());
        assert!(SName::from_str("bob@bitcoin").is_ok());
        assert!(SName::from_str("hello.bob@bitcoin").is_ok());

        let example = SName::from_str("hello.bob@bitcoin").unwrap();
        assert_eq!(example.label_count(), 3);
        let mut iter = example.iter();
        assert_eq!(iter.next(), Some(b"hello" as &[u8]));
        assert_eq!(iter.next(), Some(b"bob" as &[u8]));
        assert_eq!(iter.next(), Some(b"bitcoin" as &[u8]));
        assert_eq!(iter.next(), None);
        assert_eq!(
            example.to_bytes(),
            b"\x05hello\x03bob\x07bitcoin\x00" as &[u8]
        );
    }

    #[test]
    fn test_hyphens_from_string() {
        assert!(SName::from_str("@my-space").is_ok());
        assert!(SName::from_str("my-handle@bitcoin").is_ok());
        assert!(SName::from_str("a-b-c@my-space").is_ok());

        assert!(SName::from_str("@-bitcoin").is_err());
        assert!(SName::from_str("@bitcoin-").is_err());
        assert!(SName::from_str("-alice@bitcoin").is_err());
        assert!(SName::from_str("alice-@bitcoin").is_err());

        assert!(SName::from_str("@bit--coin").is_err());
        assert!(SName::from_str("al--ice@bitcoin").is_err());
    }

    #[test]
    fn test_hyphens_from_bytes() {
        assert!(SName::try_from(b"\x09my-handle\x07bitcoin\x00" as &[u8]).is_ok());
        assert!(SName::try_from(b"\x04-bob\x00" as &[u8]).is_err());
        assert!(SName::try_from(b"\x04bob-\x00" as &[u8]).is_err());
        assert!(SName::try_from(b"\x05b--ob\x00" as &[u8]).is_err());
    }

    #[test]
    fn test_invalid_characters() {
        assert!(SName::from_str("@Bitcoin").is_err());
        assert!(SName::from_str("Alice@bitcoin").is_err());
        assert!(SName::from_str("@bit_coin").is_err());
        assert!(SName::from_str("al!ce@bitcoin").is_err());
        assert!(SName::from_str("@bit coin").is_err());
        assert!(SName::try_from(b"\x03Bob\x00" as &[u8]).is_err());
    }

    #[test]
    fn test_numeric_labels() {
        assert!(SName::from_str("@123").is_ok());
        assert!(SName::from_str("456@123").is_ok());
        assert!(SName::from_str("a1b2@c3d4").is_ok());
    }

    #[test]
    fn test_numeric_spaces() {
        assert!(SName::from_str("#12-12-0").is_ok());
        assert!(SName::from_str("alice#12-12-0").is_ok());
        assert!(SName::from_str("key.wallet#800000-3-1").is_ok());

        assert!(SName::from_str("#").is_err());
        assert!(SName::from_str("#12-12").is_err());
        assert!(SName::from_str("#12-12-0#3-4-0").is_err());

        let root = SName::from_str("#12-12-0").unwrap();
        assert_eq!(root.to_string(), "#12-12-0");
        assert_eq!(root.label_count(), 1);

        let handle = SName::from_str("alice#12-12-0").unwrap();
        assert_eq!(handle.to_string(), "alice#12-12-0");
        assert_eq!(handle.label_count(), 2);

        let deep = SName::from_str("key.wallet#800000-3-1").unwrap();
        assert_eq!(deep.to_string(), "key.wallet#800000-3-1");
        assert_eq!(deep.label_count(), 3);

        assert!(root.space().unwrap().is_numeric());
        assert!(root.subspace().is_none());
        assert!(handle.space().unwrap().is_numeric());
        assert_eq!(handle.subspace().unwrap().to_string(), "alice");
    }

    #[test]
    fn test_punycode() {
        assert!(SName::from_str("@xn--y9jia").is_ok());
        assert!(SName::from_str("alice@xn--y9jia").is_ok());
        assert!(SName::from_str("xn--y9jia@bitcoin").is_ok());
        assert!(SName::from_str("@xn--").is_err());
        assert!(SName::from_str("@ab--cd").is_err());
        assert!(SName::try_from(b"\x09xn--y9jia\x00" as &[u8]).is_ok());
    }

    #[test]
    fn test_space_and_subspace() {
        let name = SName::from_str("alice@bitcoin").unwrap();
        assert_eq!(name.space().unwrap().to_string(), "@bitcoin");
        assert_eq!(name.subspace().unwrap().to_string(), "alice");

        let root = SName::from_str("@bitcoin").unwrap();
        assert_eq!(root.space().unwrap().to_string(), "@bitcoin");
        assert!(root.subspace().is_none());

        let deep = SName::from_str("key.wallet@bitcoin").unwrap();
        assert_eq!(deep.space().unwrap().to_string(), "@bitcoin");
        assert_eq!(deep.subspace().unwrap().to_string(), "wallet");
    }

    #[test]
    fn test_roundtrip_string() {
        let names = &[
            "@bitcoin",
            "alice@bitcoin",
            "hello.world@bitcoin",
            "@my-space",
            "my-handle@my-space",
        ];
        for &name in names {
            let parsed = SName::from_str(name).unwrap();
            assert_eq!(parsed.to_string(), name);
        }
    }

    #[test]
    fn test_roundtrip_bytes() {
        let name = SName::from_str("alice@bitcoin").unwrap();
        let bytes = name.to_bytes();
        let restored = SName::try_from(bytes).unwrap();
        assert_eq!(name, restored);
    }
}