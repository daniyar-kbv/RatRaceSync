use super::{invalid, io};
use ed25519_dalek::{Signer, SigningKey};
use prost::{
    Message,
    encoding::{decode_varint, encode_varint},
};
use rat_race_engine::Integer;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) const PROFILE: &[u8] = b"RatRaceSync/Classic101/redemption/v1";
pub(crate) fn field(out: &mut Vec<u8>, tag: u32, value: &[u8]) {
    encode_varint(u64::from(tag) * 8 + 2, out);
    encode_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}
pub(crate) fn message(parts: &[(u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, data) in parts {
        field(&mut out, *tag, data);
    }
    out
}
// This message family consists only of required, singular, length-delimited fields.
fn minimal_varint(input: &mut &[u8]) -> io::Result<u64> {
    let length = input.len();
    let value = decode_varint(input).map_err(io::Error::other)?;
    if length - input.len() != prost::encoding::encoded_len_varint(value) {
        return Err(invalid("nonminimal varint"));
    }
    Ok(value)
}
pub(crate) fn fields<'a>(mut bytes: &'a [u8], tags: &[u32]) -> io::Result<BTreeMap<u32, &'a [u8]>> {
    let mut out = BTreeMap::new();
    while !bytes.is_empty() {
        let key = minimal_varint(&mut bytes)?;
        let tag = u32::try_from(key >> 3).map_err(io::Error::other)?;
        if key & 7 != 2 || !tags.contains(&tag) || out.contains_key(&tag) {
            return Err(invalid("invalid field"));
        }
        let len = usize::try_from(minimal_varint(&mut bytes)?).map_err(io::Error::other)?;
        let (data, rest) = bytes
            .split_at_checked(len)
            .ok_or(invalid("truncated field"))?;
        out.insert(tag, data);
        bytes = rest;
    }
    if out.len() != tags.len() {
        return Err(invalid("missing field"));
    }
    Ok(out)
}
#[derive(Clone, Debug)]
pub struct Command {
    pub session: Vec<u8>,
    pub actor: Vec<u8>,
    pub request: [u8; 16],
    pub guard: [u8; 32],
    pub observed: i64,
    pub position: Vec<u8>,
    pub units: Integer,
}
impl Command {
    fn leaf(&self) -> Vec<u8> {
        message(&[(1, &self.position), (2, self.units.to_string().as_bytes())])
    }
    pub fn body(&self) -> Vec<u8> {
        message(&[
            (1, PROFILE),
            (2, &self.session),
            (3, &self.actor),
            (4, &self.request),
            (
                5,
                &message(&[(1, &self.observed.to_be_bytes()), (2, &self.guard)]),
            ),
            (11, &message(&[(109, &self.leaf())])),
        ])
    }
    pub fn sign(&self, key: &SigningKey) -> super::Signed {
        let body = self.body();
        super::Signed(message(&[(1, &body), (2, &key.sign(&body).to_bytes())]))
    }
    pub(crate) fn parse(body: &[u8]) -> io::Result<Self> {
        let f = fields(body, &[1, 2, 3, 4, 5, 11])?;
        let leaf = fields(fields(f[&11], &[109])?[&109], &[1, 2])?;
        let req: [u8; 16] = f[&4].try_into().map_err(io::Error::other)?;
        if f[&1] != PROFILE
            || req[6] >> 4 != 4
            || req[8] >> 6 != 2
            || [f[&2], f[&3], leaf[&1]]
                .iter()
                .any(|x| x.is_empty() || x.len() > 64)
        {
            return Err(invalid("unsupported profile or identifier"));
        }
        let units: Integer = std::str::from_utf8(leaf[&2])
            .map_err(io::Error::other)?
            .parse()
            .map_err(|_| invalid("invalid units"))?;
        if units <= 0.into() {
            return Err(invalid("nonpositive units"));
        }
        let g = fields(f[&5], &[1, 2])?;
        Ok(Self {
            session: f[&2].into(),
            actor: f[&3].into(),
            request: req,
            observed: i64::from_be_bytes(g[&1].try_into().map_err(io::Error::other)?),
            guard: g[&2].try_into().map_err(io::Error::other)?,
            position: leaf[&1].into(),
            units,
        })
    }
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        hash(
            b"semantic-intent",
            &[
                PROFILE,
                &self.session,
                &self.actor,
                &self.request,
                &self.observed.to_be_bytes(),
                &self.guard,
                &109u16.to_be_bytes(),
                &self.position,
                self.units.to_string().as_bytes(),
            ],
        )
    }
}
pub(crate) fn hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut sha = Sha256::new();
    for v in std::iter::once(&domain).chain(fields) {
        sha.update((v.len() as u64).to_be_bytes());
        sha.update(v)
    }
    sha.finalize().into()
}
#[derive(Clone, PartialEq, Message)]
pub struct Applied {
    #[prost(bytes = "vec", tag = "1")]
    pub position: Vec<u8>,
    #[prost(int32, tag = "2")]
    pub principal_per_unit: i32,
    #[prost(string, tag = "3")]
    pub units_redeemed: String,
    #[prost(string, tag = "4")]
    pub principal_returned: String,
    #[prost(string, tag = "5")]
    pub units_before: String,
    #[prost(string, tag = "6")]
    pub units_after: String,
    #[prost(string, tag = "7")]
    pub cash_before: String,
    #[prost(string, tag = "8")]
    pub cash_after: String,
    #[prost(string, tag = "9")]
    pub monthly_removed: String,
    #[prost(string, tag = "10")]
    pub lot_income_before: String,
    #[prost(string, tag = "11")]
    pub lot_income_after: String,
    #[prost(string, tag = "12")]
    pub total_income_before: String,
    #[prost(string, tag = "13")]
    pub total_income_after: String,
}
