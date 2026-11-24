//! Deterministic financial operations over authoritative game state.

mod integer;
mod lobby;
pub use integer::{Integer, InvalidInteger};
pub use lobby::{ClaimError, LobbyCapacity, LobbySeating, SeatId};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PlayerId(Box<[u8]>);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PositionId(Box<[u8]>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyIdentifier;

fn identifier_bytes(bytes: &[u8]) -> Result<Box<[u8]>, EmptyIdentifier> {
    if bytes.is_empty() {
        return Err(EmptyIdentifier);
    }
    Ok(bytes.into())
}

impl AsRef<[u8]> for PlayerId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PlayerId {
    type Error = EmptyIdentifier;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        identifier_bytes(bytes).map(Self)
    }
}

impl TryFrom<&[u8]> for PositionId {
    type Error = EmptyIdentifier;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        identifier_bytes(bytes).map(Self)
    }
}

/// The immutable acquisition terms of the two supported certificates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateSource {
    Principal4000,
    Principal5000,
}

impl CertificateSource {
    fn principal(self) -> i64 {
        match self {
            Self::Principal4000 => 4000,
            Self::Principal5000 => 5000,
        }
    }

    fn monthly_income_per_unit(self) -> i64 {
        match self {
            Self::Principal4000 | Self::Principal5000 => 20,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateLot {
    pub source: CertificateSource,
    pub units: Integer,
}

/// Financial state owned by one player. Each certificate position represents
/// a distinct acquisition lot. Monthly income includes other income streams.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Portfolio {
    pub owner: PlayerId,
    pub cash: Integer,
    pub monthly_income: Integer,
    pub certificates: BTreeMap<PositionId, CertificateLot>,
}

/// Financial operation 109. Prices and income come exclusively from the lot.
pub struct RedeemCertificate {
    pub position: PositionId,
    pub units: Integer,
}

impl RedeemCertificate {
    pub const OPERATION: u16 = 109;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    pub before: Integer,
    pub after: Integer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Redemption {
    pub owner: PlayerId,
    pub position: PositionId,
    pub source: CertificateSource,
    pub principal_per_unit: Integer,
    pub units_redeemed: Integer,
    pub principal_returned: Integer,
    pub monthly_income_removed: Integer,
    pub units: Change,
    pub cash: Change,
    pub lot_monthly_income: Change,
    pub player_monthly_income: Change,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedemptionError {
    NoOwnedCertificate,
    InvalidUnits,
    InsufficientUnits,
    ArithmeticRange,
}

impl Portfolio {
    /// Apply the economic rule after the caller checks session authority and
    /// the material guard. All fallible calculations precede portfolio updates.
    pub fn redeem_certificate(
        &mut self,
        actor: &PlayerId,
        intent: &RedeemCertificate,
    ) -> Result<Redemption, RedemptionError> {
        use RedemptionError::*;
        if actor != &self.owner {
            return Err(NoOwnedCertificate);
        }
        let lot = self
            .certificates
            .get_mut(&intent.position)
            .ok_or(NoOwnedCertificate)?;
        let count = &intent.units;
        if *count <= 0.into() {
            return Err(InvalidUnits);
        }
        if count > &lot.units {
            return Err(InsufficientUnits);
        }

        let source = lot.source;
        let remaining = lot.units.subtract(count).ok_or(ArithmeticRange)?;
        let credit = count.multiply(source.principal()).ok_or(ArithmeticRange)?;
        let rate = source.monthly_income_per_unit();
        let removed = count.multiply(rate).ok_or(ArithmeticRange)?;
        let outcome = Redemption {
            owner: actor.clone(),
            position: intent.position.clone(),
            source,
            principal_per_unit: source.principal().into(),
            units_redeemed: count.clone(),
            cash: Change {
                before: self.cash.clone(),
                after: self.cash.add(&credit).ok_or(ArithmeticRange)?,
            },
            lot_monthly_income: Change {
                before: lot.units.multiply(rate).ok_or(ArithmeticRange)?,
                after: remaining.multiply(rate).ok_or(ArithmeticRange)?,
            },
            player_monthly_income: Change {
                before: self.monthly_income.clone(),
                after: self
                    .monthly_income
                    .subtract(&removed)
                    .ok_or(ArithmeticRange)?,
            },
            units: Change {
                before: lot.units.clone(),
                after: remaining,
            },
            principal_returned: credit,
            monthly_income_removed: removed,
        };
        if outcome.units.after == 0.into() {
            self.certificates.remove(&intent.position);
        } else {
            lot.units = outcome.units.after.clone();
        }
        self.cash = outcome.cash.after.clone();
        self.monthly_income = outcome.player_monthly_income.after.clone();
        Ok(outcome)
    }
}
