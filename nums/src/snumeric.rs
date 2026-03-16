use core::{fmt, str::FromStr};
use spaces_protocol::slabel::SLabel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SNumeric {
    block: u32,
    tx_pos: u16,
    vout: u16,
}

impl SNumeric {
    pub fn new(block: u32, tx_pos: u16, vout: u16) -> Self {
        Self { block, tx_pos, vout }
    }

    #[inline]
    pub fn block(&self) -> u32 { self.block }

    #[inline]
    pub fn tx_pos(&self) -> u16 { self.tx_pos }

    #[inline]
    pub fn vout(&self) -> u16 { self.vout }

    pub fn to_slabel(&self) -> SLabel {
        SLabel::from_str(&self.to_string()).expect("valid numeric label")
    }
}

impl TryFrom<SLabel> for SNumeric {
    type Error = SNumericParseError;

    fn try_from(label: SLabel) -> Result<Self, Self::Error> {
        let s = label.as_str_unprefixed().map_err(|_| SNumericParseError::MissingPrefix)?;
        SNumeric::from_str(s)
    }
}

#[derive(Debug)]
pub enum SNumericParseError {
    MissingPrefix,
    InvalidFormat,
    InvalidBlock(core::num::ParseIntError),
    InvalidTxPos(core::num::ParseIntError),
    InvalidVout(core::num::ParseIntError),
}

impl fmt::Display for SNumericParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SNumericParseError::MissingPrefix => f.write_str("expected '#' prefix"),
            SNumericParseError::InvalidFormat => f.write_str("expected '#<block>-<tx_pos>-<vout>' format"),
            SNumericParseError::InvalidBlock(e) => write!(f, "invalid block number: {e}"),
            SNumericParseError::InvalidTxPos(e) => write!(f, "invalid tx position: {e}"),
            SNumericParseError::InvalidVout(e) => write!(f, "invalid vout: {e}"),
        }
    }
}

impl std::error::Error for SNumericParseError {}

impl fmt::Display for SNumeric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}-{}-{}", self.block, self.tx_pos, self.vout)
    }
}

impl FromStr for SNumeric {
    type Err = SNumericParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix('#').ok_or(SNumericParseError::MissingPrefix)?;
        let mut parts = s.splitn(3, '-');
        let block_str = parts.next().ok_or(SNumericParseError::InvalidFormat)?;
        let pos_str = parts.next().ok_or(SNumericParseError::InvalidFormat)?;
        let vout_str = parts.next().ok_or(SNumericParseError::InvalidFormat)?;
        let block = block_str.parse::<u32>().map_err(SNumericParseError::InvalidBlock)?;
        let tx_pos = pos_str.parse::<u16>().map_err(SNumericParseError::InvalidTxPos)?;
        let vout = vout_str.parse::<u16>().map_err(SNumericParseError::InvalidVout)?;
        Ok(SNumeric { block, tx_pos, vout })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SNumeric {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let mut buf = [0u8; 8];
            buf[..4].copy_from_slice(&self.block.to_le_bytes());
            buf[4..6].copy_from_slice(&self.tx_pos.to_le_bytes());
            buf[6..8].copy_from_slice(&self.vout.to_le_bytes());
            serializer.serialize_bytes(&buf)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SNumeric {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            SNumeric::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let buf = <[u8; 8]>::deserialize(deserializer)?;
            Ok(SNumeric {
                block: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
                tx_pos: u16::from_le_bytes([buf[4], buf[5]]),
                vout: u16::from_le_bytes([buf[6], buf[7]]),
            })
        }
    }
}

#[cfg(feature = "borsh")]
mod borsh_impl {
    use borsh::{io, BorshDeserialize, BorshSerialize};
    use super::*;

    impl BorshSerialize for SNumeric {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.block.serialize(writer)?;
            self.tx_pos.serialize(writer)?;
            self.vout.serialize(writer)
        }
    }

    impl BorshDeserialize for SNumeric {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let block = u32::deserialize_reader(reader)?;
            let tx_pos = u16::deserialize_reader(reader)?;
            let vout = u16::deserialize_reader(reader)?;
            Ok(SNumeric { block, tx_pos, vout })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let x = SNumeric::new(800_000, 3, 1);
        let s = x.to_string();
        assert_eq!(s, "#800000-3-1");
        let y: SNumeric = s.parse().unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn zero() {
        let x = SNumeric::new(0, 0, 0);
        assert_eq!(x.to_string(), "#0-0-0");
        assert_eq!("#0-0-0".parse::<SNumeric>().unwrap(), x);
    }

    #[test]
    fn rejects_missing_prefix() {
        let err = "800000-3-1".parse::<SNumeric>().unwrap_err();
        matches!(err, SNumericParseError::MissingPrefix);
    }

    #[test]
    fn rejects_missing_vout() {
        let err = "#800000-3".parse::<SNumeric>().unwrap_err();
        matches!(err, SNumericParseError::InvalidFormat);
    }

    #[test]
    fn rejects_invalid_block() {
        let err = "#abc-3-1".parse::<SNumeric>().unwrap_err();
        matches!(err, SNumericParseError::InvalidBlock(_));
    }

    #[test]
    fn rejects_invalid_tx_pos() {
        let err = "#800000-abc-1".parse::<SNumeric>().unwrap_err();
        matches!(err, SNumericParseError::InvalidTxPos(_));
    }

    #[test]
    fn rejects_invalid_vout() {
        let err = "#800000-3-abc".parse::<SNumeric>().unwrap_err();
        matches!(err, SNumericParseError::InvalidVout(_));
    }

    #[test]
    fn slabel_roundtrip() {
        let x = SNumeric::new(800_000, 3, 1);
        let label = x.to_slabel();
        assert_eq!(label.to_string(), "#800000-3-1");
        assert!(label.is_numeric());
        let y = SNumeric::try_from(label).unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn slabel_rejects_non_numeric() {
        let label = SLabel::from_str("@example").unwrap();
        assert!(SNumeric::try_from(label).is_err());
    }
}
