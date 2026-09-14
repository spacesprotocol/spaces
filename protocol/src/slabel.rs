use alloc::string::ToString;
use alloc::{string::String, vec::Vec};
use core::{
    fmt::{Display, Formatter},
    str::FromStr,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as ErrorUtil};

use crate::{constants::RESERVED_SPACES, errors::Error};

pub const MAX_LABEL_LEN: usize = 62;
pub const PUNYCODE_PREFIX: &[u8] = b"xn--";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SLabel([u8; MAX_LABEL_LEN + 1]);

#[cfg(feature = "borsh")]
pub mod borsh_impl {
    use borsh::{BorshDeserialize, BorshSerialize, io};

    use super::*;

    impl BorshSerialize for SLabel {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            // Serialize the full label including length byte
            let len = self.0[0] as usize;
            writer.write_all(&self.0[..=len])
        }
    }

    impl BorshDeserialize for SLabel {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let mut buf = [0u8; MAX_LABEL_LEN + 1];

            // Read the length byte first
            reader.read_exact(&mut buf[..1])?;
            let len = buf[0] as usize;
            if len > MAX_LABEL_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "length exceeds maximum for the label",
                ));
            }
            // Read the label bytes
            reader.read_exact(&mut buf[1..=len])?;
            Ok(SLabel(buf))
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for SLabel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            SLabel::from_str(&s).map_err(|_| D::Error::custom("malformed name"))
        } else {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let mut buf = [0u8; MAX_LABEL_LEN + 1];
            buf.copy_from_slice(&bytes);
            Ok(SLabel(buf))
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SLabelRef<'a>(pub &'a [u8]);

impl AsRef<[u8]> for SLabel {
    fn as_ref(&self) -> &[u8] {
        let len = self.0[0] as usize;
        &self.0[..=len]
    }
}

impl<'a> AsRef<[u8]> for SLabelRef<'a> {
    fn as_ref(&self) -> &[u8] {
        let len = self.0[0] as usize;
        &self.0[..=len]
    }
}

impl FromStr for SLabel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl<const N: usize> TryFrom<&[u8; N]> for SLabel {
    type Error = Error;

    fn try_from(value: &[u8; N]) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&Vec<u8>> for SLabel {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&[u8]> for SLabel {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let name_ref: SLabelRef = value.try_into()?;
        Ok(name_ref.to_owned())
    }
}

#[derive(Debug)]
pub enum NameErrorKind {
    Empty,
    ZeroLength,
    TooLong,
    EOF,
    InvalidCharacter,
    NotCanonical,
}

impl<'a> TryFrom<&'a [u8]> for SLabelRef<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(Error::Name(NameErrorKind::Empty));
        }
        let len = value[0] as usize;
        if len == 0 {
            return Err(Error::Name(NameErrorKind::ZeroLength));
        }
        if len > MAX_LABEL_LEN {
            return Err(Error::Name(NameErrorKind::TooLong));
        }
        if len + 1 > value.len() {
            return Err(Error::Name(NameErrorKind::EOF));
        }
        let label = &value[..=len];

        // Numeric label: #<block>-<txpos>-<vout>
        if label[1] == b'#' {
            let content = &label[2..];
            // Find first dash (block-txpos boundary)
            let d1 = content
                .iter()
                .position(|&c| c == b'-')
                .filter(|&p| p > 0)
                .ok_or(Error::Name(NameErrorKind::InvalidCharacter))?;
            let rest = &content[d1 + 1..];
            // Find second dash (txpos-vout boundary)
            let d2 = rest
                .iter()
                .position(|&c| c == b'-')
                .filter(|&p| p > 0)
                .ok_or(Error::Name(NameErrorKind::InvalidCharacter))?;

            let block = &content[..d1];
            let tx_pos = &rest[..d2];
            let vout = &rest[d2 + 1..];

            if block.is_empty()
                || tx_pos.is_empty()
                || vout.is_empty()
                || !block.iter().all(|c| c.is_ascii_digit())
                || !tx_pos.iter().all(|c| c.is_ascii_digit())
                || !vout.iter().all(|c| c.is_ascii_digit())
            {
                return Err(Error::Name(NameErrorKind::InvalidCharacter));
            }

            return Ok(SLabelRef(label));
        }

        let mut verify_range = &label[1..];
        if verify_range.starts_with(PUNYCODE_PREFIX) && len > PUNYCODE_PREFIX.len() {
            verify_range = &verify_range[PUNYCODE_PREFIX.len()..]
        }

        if verify_range[0] == b'-' || verify_range[verify_range.len() - 1] == b'-' {
            return Err(Error::Name(NameErrorKind::InvalidCharacter));
        }
        let mut prev: u8 = 0;
        for c in verify_range {
            match c {
                b'-' if prev == b'-' => return Err(Error::Name(NameErrorKind::InvalidCharacter)),
                b'a'..=b'z' | b'0'..=b'9' | b'-' => {
                    prev = *c;
                    continue;
                }
                _ => return Err(Error::Name(NameErrorKind::InvalidCharacter)),
            }
        }
        Ok(SLabelRef(label))
    }
}

impl SLabel {
    pub fn as_str_unprefixed(&self) -> Result<&str, core::str::Utf8Error> {
        let label_len = self.0[0] as usize;
        let label = &self.0[1..=label_len];
        core::str::from_utf8(label)
    }

    pub fn to_string_unprefixed(&self) -> Result<String, core::str::Utf8Error> {
        self.as_str_unprefixed().map(|s| s.to_string())
    }

    pub fn from_str_unprefixed(label: &str) -> Result<Self, Error> {
        if label.is_empty() {
            return Err(Error::Name(NameErrorKind::ZeroLength));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(Error::Name(NameErrorKind::TooLong));
        }
        let mut label_bytes = [0; MAX_LABEL_LEN + 1];
        label_bytes[0] = label.len() as u8;
        label_bytes[1..=label.len()].copy_from_slice(label.as_bytes());

        SLabel::try_from(label_bytes.as_slice())
    }
}

impl TryFrom<String> for SLabel {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for SLabel {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.starts_with('#') {
            return Self::from_str_unprefixed(value);
        }
        if let Some(rest) = value.strip_prefix('@') {
            return Self::from_str_unprefixed(rest);
        }
        Err(Error::Name(NameErrorKind::NotCanonical))
    }
}

impl Display for SLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let label_str = self.as_str_unprefixed().map_err(|_| core::fmt::Error)?;
        if self.is_numeric() {
            write!(f, "{}", label_str)
        } else {
            write!(f, "@{}", label_str)
        }
    }
}

impl Display for SLabelRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.to_owned(), f)
    }
}

impl SLabel {
    pub fn as_name_ref(&self) -> SLabelRef<'_> {
        SLabelRef(&self.0)
    }

    pub fn is_numeric(&self) -> bool {
        self.0[0] > 0 && self.0[1] == b'#'
    }

    pub fn is_reserved(&self) -> bool {
        self.as_name_ref().is_reserved()
    }
}

impl SLabelRef<'_> {
    pub fn to_owned(&self) -> SLabel {
        let mut owned = SLabel([0; MAX_LABEL_LEN + 1]);
        owned.0[..self.0.len()].copy_from_slice(self.0);
        owned
    }

    pub fn is_numeric(&self) -> bool {
        self.0[0] > 0 && self.0.get(1) == Some(&b'#')
    }

    pub fn is_reserved(&self) -> bool {
        RESERVED_SPACES
            .iter()
            .any(|reserved| *reserved == self.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::ToOwned, format, string::ToString};

    use super::*;

    #[test]
    fn test_valid_label() {
        let label_str = "@example";
        let label = SLabel::try_from(label_str).unwrap();
        assert_eq!(
            label.to_string(),
            "@example",
            "Valid label should serialize correctly"
        );

        let dns_encoded = b"\x07example";
        let label = SLabel::try_from(dns_encoded).expect("valid label");
        assert_eq!(
            label.as_ref(),
            &dns_encoded[..],
            "Valid label should serialize correctly"
        );
        assert_eq!(
            label.to_string(),
            "@example",
            "Valid label should serialize correctly"
        );
    }

    #[test]
    fn test_invalid_label() {
        assert!(
            SLabel::try_from("example").is_err(),
            "Should fail if label does not start with '@'"
        );
        assert!(
            SLabel::try_from("@").is_err(),
            "Should fail if label is empty after '@'"
        );
        assert!(
            SLabel::try_from("@EXAMPLE").is_err(),
            "Should fail if label contains uppercase characters"
        );
        assert!(
            SLabel::try_from("@exampl3$").is_err(),
            "Should fail if label contains invalid characters"
        );
        assert!(
            SLabel::try_from("@example-ok").is_ok(),
            "Should work with single hyphens"
        );
        assert!(
            SLabel::try_from("@example-ok-ok2-ok3").is_ok(),
            "Multiple non consecutive hyphens should work"
        );
        assert!(
            SLabel::try_from("@example--ok").is_err(),
            "Should not work with double hyphens"
        );
        assert!(
            SLabel::try_from("@-ok").is_err(),
            "Should not work with hyphens start"
        );
        assert!(
            SLabel::try_from("@ok-").is_err(),
            "Should not work with hyphens at end"
        );
        assert!(
            SLabel::try_from("@xn--").is_err(),
            "Should not work with empty punycode"
        );
        assert!(
            SLabel::try_from("@xn---").is_err(),
            "Should not work with single hyphen punycode"
        );
        assert!(SLabel::try_from("@xn--1").is_ok(), "Should be okay");
        assert!(SLabel::try_from("@0xn--1").is_err(), "Should not be okay");
        assert!(
            SLabel::try_from("@xn--123-pretty-valid-space-ok").is_ok(),
            "Should work :("
        );
        assert!(
            SLabel::try_from(b"\x07exam").is_err(),
            "Should fail if buffer is too short"
        );

        assert_eq!(
            SLabel::try_from(b"\x02exam").unwrap().to_string(),
            "@ex",
            "Should work"
        );
        assert_eq!(
            SLabel::try_from(b"\x02exam").unwrap().as_ref(),
            b"\x02ex",
            "Should work"
        );

        assert_eq!(
            SLabel::try_from(b"\x14xn--hello-world-1234-five-six-seven")
                .unwrap()
                .as_ref(),
            b"\x14xn--hello-world-1234",
            "Should work"
        );
    }

    #[test]
    fn test_label_length() {
        let long_label = "@".to_owned() + &"a".repeat(62);
        assert!(
            SLabel::try_from(long_label.as_str()).is_ok(),
            "Should allow label with 62 characters"
        );

        let too_long_label = "@".to_owned() + &"a".repeat(63);
        assert!(
            SLabel::try_from(too_long_label.as_str()).is_err(),
            "Should fail if label exceeds 62 characters"
        );
    }

    #[test]
    fn test_display() {
        let label_str = "@example";
        let label = SLabel::try_from(label_str).unwrap();
        assert_eq!(
            format!("{}", label),
            label_str,
            "Display should match input label"
        );
    }

    #[test]
    fn test_serialization() {
        #[cfg(feature = "serde")]
        {
            use serde_json;

            let label = SLabel::try_from("@example").unwrap();
            let serialized = serde_json::to_string(&label).unwrap();
            assert_eq!(
                serialized, "\"@example\"",
                "Serialization should produce correct JSON"
            );

            let deserialized: SLabel = serde_json::from_str(&serialized).unwrap();
            assert_eq!(
                deserialized, label,
                "Deserialization should produce the original label"
            );
        }

        #[cfg(feature = "borsh")]
        {
            use borsh::{from_slice, to_vec};
            let label = SLabel::try_from("@example").unwrap();
            let serialized = to_vec(&label).expect("encoded");

            assert_eq!(
                serialized.len(),
                label.as_ref().len(),
                "Serialization should produce correct length"
            );
            let deserialized: SLabel = from_slice(&serialized).expect("deserialize");
            assert_eq!(
                deserialized, label,
                "Deserialization should produce the original label"
            );
        }
    }

    #[test]
    fn test_empty_and_null_cases() {
        assert!(SLabel::try_from("").is_err());
        assert!(SLabel::try_from("@").is_err());
        assert!(SLabel::try_from(b"").is_err());
        assert!(SLabel::try_from(b"\x00").is_err());
    }

    #[test]
    fn test_unicode_and_special_chars() {
        assert!(SLabel::try_from("@café").is_err());
        assert!(SLabel::try_from("@test\x00test").is_err());
        assert!(SLabel::try_from("@test\ntest").is_err());
    }

    #[test]
    fn test_edge_length_cases() {
        assert!(SLabel::try_from(b"\xff").is_err()); // Length byte but no content
        assert!(SLabel::try_from(b"\x01").is_err()); // Length byte claims 1 but no content
    }

    #[test]
    fn test_punycode_edge_cases() {
        assert!(SLabel::try_from("@xn").is_ok());
        assert!(SLabel::try_from("@xn-").is_err());
        assert!(SLabel::try_from("@xn--").is_err());
        assert!(SLabel::try_from("@xxn--test").is_err());
    }

    #[test]
    fn test_numeric_valid() {
        let label = SLabel::try_from("#800000-3-1").unwrap();
        assert_eq!(label.to_string(), "#800000-3-1");
        assert!(label.is_numeric());

        let label = SLabel::try_from("#0-0-0").unwrap();
        assert_eq!(label.to_string(), "#0-0-0");
        assert!(label.is_numeric());

        let label = SLabel::try_from("#1-1-0").unwrap();
        assert_eq!(label.to_string(), "#1-1-0");

        // Large values
        let label = SLabel::try_from("#4294967295-65535-65535").unwrap();
        assert_eq!(label.to_string(), "#4294967295-65535-65535");
    }

    #[test]
    fn test_numeric_invalid() {
        // Just "#" with nothing after
        assert!(SLabel::try_from("#").is_err(), "bare # should be invalid");

        // Missing separators
        assert!(SLabel::try_from("#123").is_err(), "missing dashes");

        // Only two parts (missing vout)
        assert!(SLabel::try_from("#123-4").is_err(), "missing vout");

        // No digits before first dash
        assert!(
            SLabel::try_from("#-3-1").is_err(),
            "no digits before first dash"
        );

        // No digits between dashes
        assert!(
            SLabel::try_from("#3--1").is_err(),
            "no digits between dashes"
        );

        // No digits after second dash
        assert!(
            SLabel::try_from("#3-4-").is_err(),
            "no digits after second dash"
        );

        // Non-digit characters
        assert!(SLabel::try_from("#abc-3-1").is_err(), "letters in block");
        assert!(SLabel::try_from("#3-abc-1").is_err(), "letters in txpos");
        assert!(SLabel::try_from("#3-4-abc").is_err(), "letters in vout");

        // Too many dashes
        assert!(SLabel::try_from("#3-4-5-6").is_err(), "four parts");

        // Spaces
        assert!(SLabel::try_from("# 3-4-1").is_err(), "space in numeric");

        // Dash only content
        assert!(SLabel::try_from("#-").is_err(), "just dash after #");
    }

    #[test]
    fn test_numeric_is_numeric() {
        let named = SLabel::try_from("@example").unwrap();
        assert!(!named.is_numeric());

        let numeric = SLabel::try_from("#100-5-0").unwrap();
        assert!(numeric.is_numeric());
    }

    #[test]
    fn test_numeric_display_no_at_prefix() {
        let label = SLabel::try_from("#100-5-0").unwrap();
        // Should display as "#100-5-0" NOT "@#100-5-0"
        assert_eq!(format!("{}", label), "#100-5-0");
    }

    #[test]
    fn test_numeric_fromstr_roundtrip() {
        let original = "#999-42-7";
        let label = SLabel::from_str(original).unwrap();
        assert_eq!(label.to_string(), original);
    }

    #[test]
    fn test_numeric_raw_bytes() {
        let label = SLabel::try_from("#1-2-3").unwrap();
        // Content stored is "#1-2-3" (6 bytes), length byte = 6
        let raw = label.as_ref();
        assert_eq!(raw[0], 6); // length
        assert_eq!(&raw[1..], b"#1-2-3");
    }

    #[test]
    fn test_numeric_slabelref() {
        // Build raw bytes: length + "#1-2-3"
        let bytes = b"\x06#1-2-3";
        let label_ref = SLabelRef::try_from(bytes.as_slice()).unwrap();
        assert!(label_ref.is_numeric());
        let owned = label_ref.to_owned();
        assert!(owned.is_numeric());
        assert_eq!(owned.to_string(), "#1-2-3");
    }
}
