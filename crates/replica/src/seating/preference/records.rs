use super::*;

fn effect(parts: &[&[u8]]) -> effect::Effect {
    let fields: Vec<_> = parts
        .iter()
        .enumerate()
        .map(|(i, v)| ((i + 1) as u32, *v))
        .collect();
    effect::Effect {
        record: message(&fields),
        facts: frame(parts),
    }
}

pub(in crate::seating) fn commit(
    r: &Replica,
    db: &Transaction<'_>,
    index: u64,
    g: &SeatCommandGuard,
    tr: Transition,
) -> io::Result<effect::Effect> {
    let m = g.preference_material()?;
    let after = m
        .setup
        .checked_add(1)
        .ok_or(invalid("setup revision overflow"))?;
    let before = m.setup.to_be_bytes();
    let next = after.to_be_bytes();
    let old_ready = [u8::from(m.own.ready)];
    let old_dream = m.own.dream.map(DreamId::get);
    let result = match tr {
        Transition::Select(id) => {
            db.execute(
                "INSERT INTO dream_history(actor,idx,dream) VALUES(?,?,?)",
                params![g.actor, index.to_be_bytes(), id.get()],
            )
            .map_err(io::Error::other)?;
            let revisions = message(&[(1, &before), (2, &next)]);
            let flags = message(&[(1, &old_ready), (2, &[0])]);
            effect::Effect {
                record: message(&[
                    (1, &g.actor),
                    (2, old_dream.as_slice()),
                    (3, &[id.get()]),
                    (4, &revisions),
                    (5, &flags),
                ]),
                facts: frame(&[
                    &g.actor,
                    old_dream.as_slice(),
                    &[id.get()],
                    &before,
                    &next,
                    &old_ready,
                    &[0],
                ]),
            }
        }
        Transition::Acknowledge(value) => {
            db.execute(
                "INSERT INTO ready_history(actor,idx,ready) VALUES(?,?,?)",
                params![g.actor, index.to_be_bytes(), value],
            )
            .map_err(io::Error::other)?;
            let seat = m.seat.ok_or(invalid("missing acknowledged seat"))?.get();
            let ack = m.ack.map(u64::to_be_bytes);
            let prev = ack.as_ref().map_or(&[][..], |a| a.as_slice());
            let revisions = message(&[
                (1, &before),
                (2, &next),
                (3, &g.layout.to_be_bytes()),
                (4, &m.seat_revision.to_be_bytes()),
                (5, prev),
                (6, &index.to_be_bytes()),
            ]);
            let new = [u8::from(value)];
            let kind = [if m.own.ready == value { 2 } else { 1 }];
            effect::Effect {
                record: message(&[
                    (1, &old_ready),
                    (2, &new),
                    (3, &revisions),
                    (4, &kind),
                    (5, &g.actor),
                    (6, &[seat]),
                    (7, old_dream.as_slice()),
                ]),
                facts: frame(&[
                    &old_ready,
                    &new,
                    &before,
                    &next,
                    &g.layout.to_be_bytes(),
                    &m.seat_revision.to_be_bytes(),
                    prev,
                    &index.to_be_bytes(),
                    &kind,
                    &g.actor,
                    &[seat],
                    old_dream.as_slice(),
                ]),
            }
        }
        Transition::Unchanged => return Err(invalid("unchanged setup cannot emit an event")),
    };
    r.advance_setup(db, index, after)?;
    Ok(result)
}
pub(in crate::seating) fn unchanged(g: &SeatCommandGuard) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let m = g.preference_material()?;
    let TableAction::Preference(LobbyPreference::Ready(value)) = g.action else {
        return Err(invalid("ineligible unchanged operation"));
    };
    let ready = [u8::from(value)];
    let ack = m
        .ack
        .ok_or(invalid("missing original acknowledgment"))?
        .to_be_bytes();
    let seat = [m.seat.ok_or(invalid("missing owned seat"))?.get()];
    let dream = [m.own.dream.ok_or(invalid("missing selection"))?.get()];
    let w = effect(&[
        &g.actor,
        &ready,
        &ready,
        &ready,
        &seat,
        &dream,
        &m.setup.to_be_bytes(),
        &g.layout.to_be_bytes(),
        &m.seat_revision.to_be_bytes(),
        &ack,
        &[],
    ]);
    Ok((
        message(&[(14, &message(&[(208, &w.record)]))]),
        frame(&[&14u16.to_be_bytes(), &208u16.to_be_bytes(), &w.facts]),
    ))
}
