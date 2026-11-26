use super::*;

pub(super) struct Effect {
    pub(super) record: Vec<u8>,
    pub(super) facts: Vec<u8>,
}

// An occupancy change advances setup and invalidates the actor's acknowledgment.
pub(super) fn commit(
    r: &Replica,
    db: &Transaction<'_>,
    index: u64,
    g: &SeatCommandGuard,
    action: SeatAction,
    tr: SeatTransition,
) -> io::Result<Effect> {
    let before = setup_revision(db)?;
    let after = before
        .checked_add(1)
        .ok_or(invalid("setup revision overflow"))?;
    let layout = g.layout.to_be_bytes();
    let prior_ready = [u8::from(
        r.lobby_format.is_some_and(lobby::LobbyFormat::preferences)
            && preference::effective(db, &g.actor, index)?.ready,
    )];
    let ready = message(&[(1, &prior_ready), (2, &[0])]);
    let (source_revision, target_revision) = match &g.material {
        Dependencies::Occupancy(m) => (m.source_revision, m.target_revision),
        Dependencies::Legacy => (0, 0),
        _ => return Err(invalid("expected occupancy dependencies")),
    };
    let mut numbers = vec![layout, layout];
    for (id, owner, prior) in [
        (tr.from, None, source_revision),
        (tr.to, Some(g.actor.as_slice()), target_revision),
    ] {
        if let Some(id) = id {
            let next = prior
                .checked_add(1)
                .ok_or(invalid("seat revision overflow"))?;
            if r.seat_changes() {
                db.execute("INSERT INTO seat_history(seat,idx,revision,changed_by,occupant) VALUES(?,?,?,?,?)",
                    params![id.get(), index.to_be_bytes(), next.to_be_bytes(), g.actor, owner]).map_err(io::Error::other)?;
            } else {
                let mut occupied = claims(db)?;
                occupied.push(Occupancy {
                    seat: id.get(),
                    actor: g.actor.clone(),
                    index,
                });
                store::put(db, "seat_claims", &occupied)?;
            }
            numbers.extend([prior.to_be_bytes(), next.to_be_bytes()]);
        }
    }
    r.advance_setup(db, index, after)?;
    numbers.extend([before.to_be_bytes(), after.to_be_bytes()]);
    let revisions = message(
        &numbers
            .iter()
            .zip(1..)
            .map(|(n, tag)| (tag, n.as_slice()))
            .collect::<Vec<_>>(),
    );
    let old = tr.from.map(SeatId::get);
    let new = tr.to.map(SeatId::get);
    let actor = g.actor.as_slice();
    let (record, mut facts) = match action {
        SeatAction::Claim(_) => (
            message(&[
                (1, actor),
                (2, &[]),
                (3, new.as_slice()),
                (4, &revisions),
                (5, &ready),
            ]),
            vec![actor, &[][..], new.as_slice()],
        ),
        SeatAction::Release => (
            message(&[
                (1, old.as_slice()),
                (2, old.as_slice()),
                (3, &revisions),
                (4, &ready),
            ]),
            vec![old.as_slice(), old.as_slice()],
        ),
        SeatAction::Change(_) => {
            let ownership = message(&[(1, actor), (2, &[]), (3, &[]), (4, actor)]);
            (
                message(&[
                    (1, old.as_slice()),
                    (2, new.as_slice()),
                    (3, &ownership),
                    (4, &revisions),
                    (5, &ready),
                ]),
                vec![
                    old.as_slice(),
                    new.as_slice(),
                    actor,
                    &[][..],
                    &[][..],
                    actor,
                ],
            )
        }
    };
    facts.extend(numbers.iter().map(|n| n.as_slice()));
    facts.extend([&prior_ready[..], &[0][..]]);
    Ok(Effect {
        record,
        facts: frame(&facts),
    })
}
