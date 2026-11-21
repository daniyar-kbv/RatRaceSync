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
