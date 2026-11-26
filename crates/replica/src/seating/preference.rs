use super::*;
use rat_race_engine::DreamId;

pub use rat_race_engine::LobbyPreference;
pub(super) use rat_race_engine::PreferenceTransition as Transition;

pub(super) fn operation(action: LobbyPreference) -> (u32, Option<u8>) {
    match action {
        LobbyPreference::Dream(id) => (207, Some(id.get())),
        LobbyPreference::Ready(b) => (208, Some(u8::from(b))),
    }
}
pub(super) fn parse(op: u32, value: u8) -> io::Result<LobbyPreference> {
    match (op, value) {
        (207, n) => DreamId::new(n)
            .map(LobbyPreference::Dream)
            .ok_or(invalid("unsupported selection")),
        (208, 0) => Ok(LobbyPreference::Ready(false)),
        (208, 1) => Ok(LobbyPreference::Ready(true)),
        _ => Err(invalid("invalid setup intent")),
    }
}
mod records;
mod witness;
pub(super) use records::{commit, unchanged};
pub use witness::{LobbyIntent, OwnPreferenceRead};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnLobbyPreference {
    pub dream: Option<DreamId>,
    pub ready: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Material {
    pub(super) setup: u64,
    seat: Option<SeatId>,
    seat_revision: u64,
    own: OwnLobbyPreference,
    ack: Option<u64>,
    revision: [u8; 32],
    origin: [u8; 32],
}
pub(super) struct History {
    dream: Option<DreamId>,
    dream_index: Option<u64>,
    pub(super) ready: bool,
    pub(super) ack: Option<u64>,
}
pub(super) fn history(db: &Connection, actor: &[u8], index: u64) -> io::Result<History> {
    let at = index.to_be_bytes();
    let dream = db
        .query_row(
            "SELECT idx,dream FROM dream_history WHERE actor=? AND idx<=?
             ORDER BY idx DESC LIMIT 1",
            params![actor, at],
            |r| Ok((r.get::<_, [u8; 8]>(0)?, r.get::<_, u8>(1)?)),
        )
        .optional()
        .map_err(io::Error::other)?;
    let ready = db
        .query_row(
            "SELECT idx,ready FROM ready_history WHERE actor=? AND idx<=?
             ORDER BY idx DESC LIMIT 1",
            params![actor, at],
            |r| Ok((r.get::<_, [u8; 8]>(0)?, r.get::<_, bool>(1)?)),
        )
        .optional()
        .map_err(io::Error::other)?;
    let dream_index = dream.map(|(i, _)| u64::from_be_bytes(i));
    let dream = dream
        .map(|(_, n)| DreamId::new(n).ok_or(invalid("invalid stored selection")))
        .transpose()?;
    let mut ack = None;
    let mut effective = false;
    if let Some((i, value)) = ready {
        let seat = db
            .query_row(
                "SELECT idx FROM seat_history WHERE changed_by=? AND idx<=?
             ORDER BY idx DESC LIMIT 1",
                params![actor, at],
                |r| r.get::<_, [u8; 8]>(0),
            )
            .optional()
            .map_err(io::Error::other)?;
        let i = u64::from_be_bytes(i);
        let mut current = seat.is_some_and(|seat| u64::from_be_bytes(seat) < i)
            && dream_index.is_some_and(|d| d < i);
        for name in ["first_member", "third_member"] {
            if store::meta::<JoinedMember>(db, name)?
                .is_some_and(|m| i < m.log_id.index && m.log_id.index <= index)
            {
                current = false;
            }
        }
        if departure::left_at(db, index)?.is_some_and(|d| i < d.log_id.index) {
            current = false;
        }
        if current {
            effective = value;
            ack = Some(i);
        }
    }
    Ok(History {
        dream,
        dream_index,
        ready: effective,
        ack,
    })
}
pub(super) fn acknowledgment(db: &Connection, actor: &[u8]) -> io::Result<(bool, Option<u64>)> {
    let h = history(db, actor, u64::MAX)?;
    Ok((h.ready, h.ack))
}
pub(super) fn effective(
    db: &Connection,
    actor: &[u8],
    index: u64,
) -> io::Result<OwnLobbyPreference> {
    let h = history(db, actor, index)?;
    Ok(OwnLobbyPreference {
        dream: h.dream,
        ready: h.ready,
    })
}

fn ineligible() -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, "player setup is ineligible")
}
pub(super) fn evaluate(
    db: &Connection,
    table: &Snapshot,
    actor: &[u8],
    index: u64,
    action: LobbyPreference,
) -> io::Result<(Change, Dependencies)> {
    let h = history(db, actor, index)?;
    let seat = table
        .seating()
        .seats()
        .find(|(_, p)| p.is_some_and(|p| p.as_ref() == actor))
        .map(|(s, _)| s);
    let tr = action
        .transition(seat, h.dream, h.ack.map(|_| h.ready))
        .ok_or_else(ineligible)?;
    // The original signed selection (or signed Create for absence) supplies entropy
    // unavailable from a viewer's 23 possible choices. No extra revision token is written.
    let (revision, origin): ([u8; 32], [u8; 32]) = match h.dream_index {
        Some(i) => db.query_row(
            "SELECT log_id,digest FROM archive WHERE idx=?",
            [i.to_be_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ),
        None => db.query_row(
            "SELECT log_id,digest FROM archive WHERE event_count=1 ORDER BY idx LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ),
    }
    .map_err(io::Error::other)?;
    let m = Material {
        setup: resize::observed_setup(db, index)?,
        seat,
        seat_revision: seat.map_or(0, |s| table.revision(s)),
        own: OwnLobbyPreference {
            dream: h.dream,
            ready: h.ready,
        },
        ack: h.ack,
        revision,
        origin,
    };
    Ok((Change::Preference(tr), Dependencies::Preference(m)))
}
