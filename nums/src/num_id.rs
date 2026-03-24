use core::{fmt, str::FromStr};
use bech32::{self, Hrp, Bech32m};
use bitcoin::{ScriptBuf};
use spaces_protocol::hasher::{Hash, KeyHash, KeyHasher};
use crate::{ns_hash, KeyKind};

pub const NUM_HRP: &str = "num";

impl KeyHash for NumId {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NumId(pub(crate) [u8; 32]);


impl NumId {
    #[inline]
    pub fn from_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }
    #[inline]
    pub fn as_slice(&self) -> &[u8] { &self.0 }
    #[inline]
    pub fn to_bytes(self) -> [u8; 32] { self.0 }

    pub fn from_spk<H: KeyHasher>(spk: ScriptBuf) -> Self {
        Self(ns_hash::<H>(KeyKind::NumId, H::hash(&spk.as_bytes())))
    }
}

impl From<NumId> for Hash {
    fn from(value: NumId) -> Self {
        value.0
    }
}

#[derive(Debug)]
pub enum NumIdParseError {
    Bech32(bech32::DecodeError),
    InvalidHrp,
    InvalidLen,
}

impl fmt::Display for NumIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NumIdParseError::Bech32(e) => write!(f, "bech32 decode error: {e}"),
            NumIdParseError::InvalidHrp => f.write_str("invalid HRP for num id"),
            NumIdParseError::InvalidLen => f.write_str("invalid data length; expected 32 bytes"),
        }
    }
}

impl std::error::Error for NumIdParseError {}

#[cfg(feature = "serde")]
impl serde::Serialize for NumId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NumId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::str::FromStr;
        let s = String::deserialize(deserializer)?;
        NumId::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "borsh")]
mod borsh_impl {
    use borsh::{io, BorshDeserialize, BorshSerialize};
    use super::*;

    impl BorshSerialize for NumId {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            writer.write_all(&self.0)
        }
    }

    impl BorshDeserialize for NumId {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let mut bytes = [0u8; 32];
            reader.read_exact(&mut bytes)?;
            Ok(NumId(bytes))
        }
    }
}

impl From<bech32::DecodeError> for NumIdParseError {
    fn from(e: bech32::DecodeError) -> Self { NumIdParseError::Bech32(e) }
}

impl fmt::Display for NumId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse(NUM_HRP).map_err(|_| fmt::Error)?;
        let s = bech32::encode::<Bech32m>(hrp, &self.0).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

impl FromStr for NumId {
    type Err = NumIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp.as_str() != NUM_HRP { return Err(NumIdParseError::InvalidHrp); }
        if data.len() != 32 { return Err(NumIdParseError::InvalidLen); }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data);
        Ok(NumId(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::{Bech32m};

    #[test]
    fn num_id_roundtrip() {
        let x = NumId([7u8; 32]);
        let s = x.to_string();
        let y: NumId = s.parse().unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn rejects_wrong_hrp() {
        let hrp = Hrp::parse("nope").unwrap();
        let s = bech32::encode::<Bech32m>(hrp, &[0u8; 32]).unwrap();
        let err = s.parse::<NumId>().unwrap_err();
        matches!(err, NumIdParseError::InvalidHrp);
    }

    #[test]
    fn rejects_wrong_len() {
        let hrp = Hrp::parse(NUM_HRP).unwrap();
        let s = bech32::encode::<Bech32m>(hrp, &[0u8; 31]).unwrap();
        let err = s.parse::<NumId>().unwrap_err();
        matches!(err, NumIdParseError::InvalidLen);
    }
}
