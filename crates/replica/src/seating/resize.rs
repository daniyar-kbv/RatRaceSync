use super::*;

pub(super) struct Resize {
    before: u8,
    order: Vec<SeatId>,
    occupied: Vec<(SeatId, Vec<u8>)>,
}
impl Resize {
    pub(super) fn plan(
        db: &Connection,
        index: u64,
        table: &Snapshot,
        target: LobbyCapacity,
    ) -> io::Result<Self> {
        let mut joined = 1;
        for key in ["first_member", "third_member"] {
            if store::meta::<JoinedMember>(db, key)?.is_some_and(|m| m.log_id.index <= index) {
                joined += 1;
            }
        }
        joined -= departure::departures_at(db, index)?.len();
        let order = table
            .seating()
            .resized_order(target, joined)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "target unchanged or below joined count",
                )
            })?;
        let mut occupied: Vec<_> = table
            .seating()
            .seats()
            .filter_map(|(id, owner)| owner.map(|p| (id, p.as_ref().to_vec())))
            .collect();
        occupied.sort_by(|(_, a), (_, b)| a.cmp(b));
        Ok(Self {
            before: table.seating().capacity().count(),
            order,
            occupied,
        })
    }

    pub(super) fn commit(
        &self,
        r: &Replica,
        db: &Transaction<'_>,
        index: u64,
        revision: u64,
    ) -> io::Result<effect::Effect> {
        let after = revision
            .checked_add(1)
            .ok_or(invalid("layout revision overflow"))?;
        let seats: Vec<_> = self.order.iter().map(|id| id.get()).collect();
        db.execute(
            "INSERT INTO layout_history(idx,revision,seats) VALUES(?,?,?)",
            params![index.to_be_bytes(), after.to_be_bytes(), seats],
        )
        .map_err(io::Error::other)?;
        let mut retained = Vec::new();
        let mut retained_facts = Vec::new();
        for (id, owner) in &self.occupied {
            let ready = [u8::from(
                r.lobby_format.is_some_and(lobby::LobbyFormat::preferences)
                    && preference::effective(db, owner, index)?.ready,
            )];
            wire::field(
                &mut retained,
                1,
                &message(&[(1, &[id.get()]), (2, owner), (3, &ready)]),
            );
            retained_facts.extend(frame(&[&[id.get()], owner, &ready]));
        }
        let before = [self.before];
        let target = [seats.len() as u8];
        let old = revision.to_be_bytes();
        let new = after.to_be_bytes();
        Ok(effect::Effect {
            record: message(&[
                (1, &before),
                (2, &target),
                (3, &old),
                (4, &new),
                (5, &seats),
                (6, &retained),
            ]),
            facts: frame(&[&before, &target, &old, &new, &seats, &retained_facts]),
        })
    }
}

pub(super) fn observed_setup(db: &Connection, index: u64) -> io::Result<u64> {
    let revision = db
        .query_row(
            "SELECT revision FROM setup_history WHERE idx<=? ORDER BY idx DESC LIMIT 1",
            [index.to_be_bytes()],
            |r| r.get::<_, [u8; 8]>(0),
        )
        .optional()
        .map_err(io::Error::other)?;
    match revision {
        Some(bytes) => Ok(u64::from_be_bytes(bytes)),
        None => Ok(lobby(db)?.setup_revision),
    }
}

pub(crate) struct OpenLayout {
    pub(crate) layout_revision: u64,
    pub(super) host: Vec<u8>,
    pub(crate) seats: LobbySeating,
}

pub(crate) fn layout_at(db: &Connection, index: u64) -> io::Result<OpenLayout> {
    cancellation::require_open(db, index)?;
    let created = lobby(db)?;
    let mut layout_revision = created.layout_revision;
    let mut order = created
        .seats
        .iter()
        .map(|bytes| match bytes.as_slice() {
            [n] => Ok(*n),
            _ => Err(invalid("invalid initial seat identifier")),
        })
        .collect::<io::Result<Vec<_>>>()?;
    if order.len() != created.target as usize {
        return Err(invalid("inconsistent initial seat count"));
    }
    if lobby::LobbyFormat::parse(&created.profile)?.resizable() {
        let row = db
            .query_row(
                "SELECT revision,seats FROM layout_history WHERE idx<=? ORDER BY idx DESC LIMIT 1",
                [index.to_be_bytes()],
                |r| Ok((r.get::<_, [u8; 8]>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(io::Error::other)?;
        if let Some((revision, ids)) = row {
            layout_revision = u64::from_be_bytes(revision);
            order = ids;
        }
    }
    let ids = order
        .into_iter()
        .map(|n| SeatId::new(n).ok_or(invalid("invalid seat ID")))
        .collect::<io::Result<Vec<_>>>()?;
    let seats = LobbySeating::from_order(&ids).ok_or(invalid("invalid physical seat order"))?;
    Ok(OpenLayout {
        host: created.host,
        layout_revision,
        seats,
    })
}
