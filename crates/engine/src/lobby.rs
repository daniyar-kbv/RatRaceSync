use crate::PlayerId;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SeatId(u8);
impl SeatId {
    pub fn new(value: u8) -> Option<Self> {
        (1..=10).contains(&value).then_some(Self(value))
    }
    pub fn get(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    UnknownSeat,
    AlreadySeated,
    SeatUnavailable,
}

pub struct LobbySeating {
    occupants: BTreeMap<SeatId, Option<PlayerId>>,
}
impl LobbySeating {
    pub fn new(capacity: LobbyCapacity) -> Self {
        Self {
            occupants: capacity
                .ordered_seats()
                .map(|n| (SeatId(n), None))
                .collect(),
        }
    }
    pub fn seats(&self) -> impl Iterator<Item = (SeatId, Option<&PlayerId>)> {
        self.occupants.iter().map(|(id, p)| (*id, p.as_ref()))
    }
    pub fn occupant(&self, seat: SeatId) -> Option<&PlayerId> {
        self.occupants.get(&seat).and_then(Option::as_ref)
    }
    pub fn claim(&mut self, actor: &PlayerId, seat: SeatId) -> Result<(), ClaimError> {
        if self.occupants.values().flatten().any(|p| p == actor) {
            return Err(ClaimError::AlreadySeated);
        }
        let place = self
            .occupants
            .get_mut(&seat)
            .ok_or(ClaimError::UnknownSeat)?;
        if place.is_some() {
            return Err(ClaimError::SeatUnavailable);
        }
        *place = Some(actor.clone());
        Ok(())
    }
}

/// The host chooses a fixed physical seat order. Creation leaves every seat vacant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LobbyCapacity(u8);

impl LobbyCapacity {
    pub fn new(count: u8) -> Option<Self> {
        (2..=10).contains(&count).then_some(Self(count))
    }

    pub fn count(self) -> u8 {
        self.0
    }

    /// Stable, session-scoped initial seat identifiers in physical order.
    pub fn ordered_seats(self) -> impl Iterator<Item = u8> {
        1..=self.0
    }
}
