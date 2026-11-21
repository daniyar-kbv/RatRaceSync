use num_bigint::BigInt;
use std::{fmt, str::FromStr};

/// Exact signed whole units or dollars. Each domain value fits 128 decimal digits.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Integer(BigInt);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidInteger;

impl FromStr for Integer {
    type Err = InvalidInteger;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == "0" {
            return Ok(0.into());
        }
        let digits = text.strip_prefix('-').unwrap_or(text);
        if digits.is_empty()
            || digits.len() > 128
            || digits.starts_with('0')
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(InvalidInteger);
        }
        text.parse().map(Self).map_err(|_| InvalidInteger)
    }
}

impl From<i64> for Integer {
    fn from(value: i64) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Integer {
    fn bounded(value: BigInt) -> Option<Self> {
        (value.magnitude().to_str_radix(10).len() <= 128).then_some(Self(value))
    }

    pub(crate) fn add(&self, rhs: &Self) -> Option<Self> {
        Self::bounded(&self.0 + &rhs.0)
    }

    pub(crate) fn subtract(&self, rhs: &Self) -> Option<Self> {
        Self::bounded(&self.0 - &rhs.0)
    }

    pub(crate) fn multiply(&self, factor: i64) -> Option<Self> {
        Self::bounded(&self.0 * factor)
    }
}
