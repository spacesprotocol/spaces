use core::{fmt, str::FromStr};
use bech32::{self, Hrp, Bech32m};
use bitcoin::{ScriptBuf};
use spaces_protocol::hasher::{Hash, KeyHash, KeyHasher};
use crate::{ns_hash, KeyKind};

pub const SPTR_HRP: &str = "sptr";

impl KeyHash for Sptr {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sptr(pub(crate) [u8; 32]);

impl Sptr {
    #[inline]
    pub fn as_slice(&self) -> &[u8] { &self.0 }
    #[inline]
    pub fn to_bytes(self) -> [u8; 32] { self.0 }

    pub fn from_spk<H: KeyHasher>(spk: ScriptBuf) -> Self {
        Self(ns_hash::<H>(KeyKind::Sptr, H::hash(&spk.as_bytes())))
    }
}

impl From<Sptr> for Hash {
    fn from(value: Sptr) -> Self {
        value.0
    }
}

#[derive(Debug)]
pub enum SptrParseError {
    Bech32(bech32::DecodeError),
    InvalidHrp,
    InvalidLen,
}

impl fmt::Display for SptrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SptrParseError::Bech32(e) => write!(f, "bech32 decode error: {e}"),
            SptrParseError::InvalidHrp => f.write_str("invalid HRP for sptr"),
            SptrParseError::InvalidLen => f.write_str("invalid data length; expected 32 bytes"),
        }
    }
}

impl std::error::Error for SptrParseError {}

#[cfg(feature = "serde")]
impl serde::Serialize for Sptr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Sptr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::str::FromStr;
        let s = String::deserialize(deserializer)?;
        Sptr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "borsh")]
mod borsh_impl {
    use borsh::{io, BorshDeserialize, BorshSerialize};
    use super::*;

    impl BorshSerialize for Sptr {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            writer.write_all(&self.0)
        }
    }

    impl BorshDeserialize for Sptr {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let mut bytes = [0u8; 32];
            reader.read_exact(&mut bytes)?;
            Ok(Sptr(bytes))
        }
    }
}

impl From<bech32::DecodeError> for SptrParseError {
    fn from(e: bech32::DecodeError) -> Self { SptrParseError::Bech32(e) }
}

impl fmt::Display for Sptr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse(SPTR_HRP).map_err(|_| fmt::Error)?;
        let s = bech32::encode::<Bech32m>(hrp, &self.0).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

impl FromStr for Sptr {
    type Err = SptrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp.as_str() != SPTR_HRP { return Err(SptrParseError::InvalidHrp); }
        if data.len() != 32 { return Err(SptrParseError::InvalidLen); }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data);
        Ok(Sptr(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::{Bech32m};

    #[test]
    fn sptr_roundtrip() {
        let x = Sptr([7u8; 32]);
        let s = x.to_string();
        let y: Sptr = s.parse().unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn rejects_wrong_hrp() {
        let hrp = Hrp::parse("nope").unwrap();
        let s = bech32::encode::<Bech32m>(hrp, &[0u8; 32]).unwrap();
        let err = s.parse::<Sptr>().unwrap_err();
        matches!(err, SptrParseError::InvalidHrp);
    }

    #[test]
    fn rejects_wrong_len() {
        let hrp = Hrp::parse(SPTR_HRP).unwrap();
        let s = bech32::encode::<Bech32m>(hrp, &[0u8; 31]).unwrap();
        let err = s.parse::<Sptr>().unwrap_err();
        matches!(err, SptrParseError::InvalidLen);
    }
}
