use crate::PlayerId;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeatAction {
    Claim(SeatId),
    Release,
    Change(SeatId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeatTransition {
    pub from: Option<SeatId>,
    pub to: Option<SeatId>,
}

#[derive(Clone)]
pub struct LobbySeating {
    occupants: Vec<(SeatId, Option<PlayerId>)>,
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
    /// A layout retains physical order even when a shrink removed gaps between players.
    pub fn from_order(order: &[SeatId]) -> Option<Self> {
        if !(2..=10).contains(&order.len())
            || order
                .iter()
                .enumerate()
                .any(|(i, id)| order[..i].contains(id))
        {
            return None;
        }
        Some(Self {
            occupants: order.iter().map(|id| (*id, None)).collect(),
        })
    }

    /// Remove vacant positions from the end of physical order. Grow by appending
    /// the lowest available session seat IDs; retained IDs never move relative to each other.
    pub fn resized_order(&self, target: LobbyCapacity, joined: usize) -> Option<Vec<SeatId>> {
        let count = usize::from(target.count());
        if count < joined || count == self.occupants.len() {
            return None;
        }
        let mut order: Vec<_> = self.seats().map(|(id, _)| id).collect();
        if count < order.len() {
            for (id, owner) in self.occupants.iter().rev() {
                if order.len() == count {
                    break;
                }
                if owner.is_none() {
                    order.retain(|kept| kept != id);
                }
            }
        } else {
            for id in (1..=10).map(SeatId) {
                if order.len() == count {
                    break;
                }
                if !order.contains(&id) {
                    order.push(id);
                }
            }
        }
        (order.len() == count).then_some(order)
    }

    pub fn capacity(&self) -> LobbyCapacity {
        LobbyCapacity(self.occupants.len() as u8)
    }

    pub fn seats(&self) -> impl Iterator<Item = (SeatId, Option<&PlayerId>)> {
        self.occupants.iter().map(|(id, p)| (*id, p.as_ref()))
    }
    pub fn occupant(&self, seat: SeatId) -> Option<&PlayerId> {
        self.seats()
            .find(|(id, _)| *id == seat)
            .and_then(|(_, p)| p)
    }
    /// Validate ownership and vacancy together before either seat changes.
    pub fn transition(
        &self,
        actor: &PlayerId,
        action: SeatAction,
    ) -> Result<SeatTransition, ClaimError> {
        let from = self
            .seats()
            .find(|(_, owner)| *owner == Some(actor))
            .map(|(id, _)| id);
        let to = match action {
            SeatAction::Claim(_) if from.is_some() => return Err(ClaimError::AlreadySeated),
            SeatAction::Release | SeatAction::Change(_) if from.is_none() => {
                return Err(ClaimError::SeatUnavailable);
            }
            SeatAction::Claim(id) | SeatAction::Change(id) => {
                match self.seats().find(|(seat, _)| *seat == id).map(|(_, p)| p) {
                    None => return Err(ClaimError::UnknownSeat),
                    Some(Some(_)) => return Err(ClaimError::SeatUnavailable),
                    Some(None) => Some(id),
                }
            }
            SeatAction::Release => None,
        };
        Ok(SeatTransition { from, to })
    }

    pub fn claim(&mut self, actor: &PlayerId, seat: SeatId) -> Result<(), ClaimError> {
        self.transition(actor, SeatAction::Claim(seat))?;
        let (_, owner) = self
            .occupants
            .iter_mut()
            .find(|(id, _)| *id == seat)
            .ok_or(ClaimError::UnknownSeat)?;
        *owner = Some(actor.clone());
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
