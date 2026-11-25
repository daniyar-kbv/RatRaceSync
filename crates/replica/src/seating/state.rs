use super::*;
use std::collections::BTreeMap;

pub(super) struct Snapshot {
    table: LobbySeating,
    revisions: BTreeMap<SeatId, u64>,
}

impl Snapshot {
    pub(super) fn at(
        r: &Replica,
        db: &Connection,
        state: &OpenLayout,
        index: u64,
    ) -> io::Result<Self> {
        let mut table = state.seats.clone();
        let mut revisions = BTreeMap::new();
        if r.seat_changes() {
            let mut query = db.prepare("SELECT occupant,revision FROM seat_history WHERE seat=? AND idx<=? ORDER BY idx DESC LIMIT 1").map_err(io::Error::other)?;
            for (seat, _) in state.seats.seats() {
                let n = seat.get();
                let row = query
                    .query_row(params![n, index.to_be_bytes()], |row| {
                        Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, [u8; 8]>(1)?))
                    })
                    .optional()
                    .map_err(io::Error::other)?;
                if let Some((owner, revision)) = row {
                    revisions.insert(seat, u64::from_be_bytes(revision));
                    if let Some(owner) = owner {
                        table
                            .claim(&player(&owner)?, seat)
                            .map_err(|_| invalid("inconsistent seat ownership"))?;
                    }
                }
            }
        } else {
            for row in claims(db)?.into_iter().filter(|row| row.index <= index) {
                let seat = SeatId::new(row.seat).ok_or(invalid("invalid stored seat"))?;
                table
                    .claim(&player(&row.actor)?, seat)
                    .map_err(|_| invalid("inconsistent stored occupancy"))?;
                revisions.insert(seat, 1);
            }
        }
        Ok(Self { table, revisions })
    }
    pub(super) fn seating(&self) -> &LobbySeating {
        &self.table
    }
    pub(super) fn revision(&self, id: SeatId) -> u64 {
        self.revisions.get(&id).copied().unwrap_or(0)
    }
    pub(super) fn view(&self) -> Vec<LobbySeat> {
        self.table
            .seats()
            .map(|(id, p)| LobbySeat {
                id,
                ready: false,
                revision: self.revision(id),
                occupant: p.map(|owner| owner.as_ref().to_vec()),
            })
            .collect()
    }
    pub(super) fn transition(
        &self,
        actor: &[u8],
        action: SeatAction,
    ) -> io::Result<SeatTransition> {
        use rat_race_engine::ClaimError::*;
        self.table
            .transition(&player(actor)?, action)
            .map_err(|e| match e {
                AlreadySeated => {
                    io::Error::new(io::ErrorKind::AlreadyExists, "player already seated")
                }
                SeatUnavailable => io::Error::new(io::ErrorKind::AlreadyExists, "seat unavailable"),
                UnknownSeat => invalid("seat outside layout"),
            })
    }
}

// Every seat change advances the actor's ownership history, including a cycle back to no seat.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Material {
    pub(super) from: Option<SeatId>,
    pub(super) source_revision: u64,
    pub(super) target_revision: u64,
    pub(super) actor_index: u64,
}
impl Material {
    pub(super) fn at(
        db: &Connection,
        table: &Snapshot,
        actor: &[u8],
        index: u64,
        transition: SeatTransition,
    ) -> io::Result<Self> {
        let latest = db.query_row("SELECT idx FROM seat_history WHERE changed_by=? AND idx<=? ORDER BY idx DESC LIMIT 1",
            params![actor,index.to_be_bytes()], |row|row.get::<_,[u8;8]>(0)).optional().map_err(io::Error::other)?;
        Ok(Self {
            from: transition.from,
            source_revision: transition.from.map_or(0, |id| table.revision(id)),
            target_revision: transition.to.map_or(0, |id| table.revision(id)),
            actor_index: latest.map_or(0, u64::from_be_bytes),
        })
    }
    pub(super) fn append_guard(&self, bytes: &mut Vec<u8>) {
        wire::field(bytes, 5, &self.target_revision.to_be_bytes());
        wire::field(bytes, 6, self.from.map(SeatId::get).as_slice());
        wire::field(bytes, 7, &self.source_revision.to_be_bytes());
        wire::field(bytes, 8, &self.actor_index.to_be_bytes());
    }
}
