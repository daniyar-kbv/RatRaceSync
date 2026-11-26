use super::*;

pub(crate) fn at(db: &Connection, index: u64) -> io::Result<Option<LogId>> {
    Ok(store::meta::<LogId>(db, "cancelled_at")?.filter(|k| k.index <= index))
}
pub(crate) fn require_open(db: &Connection, index: u64) -> io::Result<()> {
    if at(db, index)?.is_some() {
        return Err(invalid("lobby cancelled"));
    }
    Ok(())
}

pub(super) fn configuration_at(db: &Connection, index: u64) -> io::Result<[u8; 32]> {
    db.query_row("SELECT log_id FROM archive WHERE idx<=? AND substr(source,1,1) IN (x'02',x'03') ORDER BY idx DESC LIMIT 1",
        [index.to_be_bytes()],|r|r.get(0)).map_err(io::Error::other)
}

pub(super) fn commit(
    r: &Replica,
    db: &Transaction<'_>,
    k: LogId,
    command: &SeatCommand,
) -> io::Result<effect::Effect> {
    let g = &command.guard;
    let Dependencies::Membership {
        setup,
        configuration,
    } = &g.material
    else {
        return Err(invalid("missing cancellation guard"));
    };
    let state = layout_at(db, u64::MAX)?;
    let seats = Snapshot::at(r.seat_changes(), db, &state, u64::MAX)?.view();
    let creator = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
    let mut members = vec![(1, creator.actor, creator.node)];
    let departed = departure::left_at(db, k.index)?;
    for name in ["first_member", "third_member"] {
        if let Some(m) = store::meta::<JoinedMember>(db, name)?
            && departed.as_ref().is_none_or(|left| left.node != m.node)
        {
            members.push((m.ordinal, m.actor, m.node));
        }
    }
    let mut closures = Vec::new();
    let mut member_facts = Vec::new();
    for (ordinal, actor, node) in members {
        let seat = seats
            .iter()
            .find(|s| s.occupant.as_deref() == Some(actor.as_slice()));
        let old_seat = seat.map(|s| s.id.get());
        let revision = seat.map(|s| s.revision.to_be_bytes());
        let revision = revision.as_ref().map_or(&[][..], |n| n.as_slice());
        let (ready, ack) = preference::acknowledgment(db, &actor)?;
        let ack = ack.map(u64::to_be_bytes);
        let ack = ack.as_ref().map_or(&[][..], |n| n.as_slice());
        let ordinal = ordinal.to_be_bytes();
        let was_ready = [u8::from(ready)];
        // Joined -> closed, original seat -> vacant, original acknowledgment -> absent.
        let facts: &[&[u8]] = &[
            &actor,
            &node.0,
            &ordinal,
            &[1],
            &[2],
            old_seat.as_slice(),
            &[],
            revision,
            &was_ready,
            &[0],
            ack,
            &[],
        ];
        let row = message(
            &facts
                .iter()
                .enumerate()
                .map(|(i, v)| ((i + 1) as u32, *v))
                .collect::<Vec<_>>(),
        );
        wire::field(&mut closures, 1, &row);
        member_facts.extend(frame(facts));
    }
    // The final game decision uses the existing quorum. Its actual configuration
    // remains available to authenticate history after all game participation closes.
    let open = [LobbyStage::Open as u8];
    let cancelled = [LobbyStage::Cancelled as u8];
    store::put(db, "cancelled_at", &k)?;
    Ok(effect::Effect {
        record: message(&[
            (1, &open),
            (2, &cancelled),
            (3, &closures),
            (4, configuration),
            (5, &[0]),
        ]),
        facts: frame(&[
            &open,
            &cancelled,
            &member_facts,
            configuration,
            &[0],
            &setup.to_be_bytes(),
            &g.layout.to_be_bytes(),
        ]),
    })
}

impl GameNode {
    pub async fn cancel_lobby_guard(&self, actor: &[u8]) -> io::Result<SeatCommandGuard> {
        self.seat_guard(actor, TableAction::Cancel).await
    }
    /// Public guard bytes from the current coordinator for the creator's installation.
    pub async fn cancellation_witness(&self, actor: &[u8]) -> io::Result<Vec<u8>> {
        Ok(self.cancel_lobby_guard(actor).await?.detached_guard())
    }

    /// Sign on the creator's installation after checking the coordinator's observed history.
    pub fn prepare_cancellation(
        &self,
        actor: &[u8],
        witness: &[u8],
        request: [u8; 16],
        key: &SigningKey,
    ) -> io::Result<Signed> {
        self.prepare_member_command(actor, witness, request, key, 210)
    }
    pub(super) fn prepare_member_command(
        &self,
        actor: &[u8],
        witness: &[u8],
        request: [u8; 16],
        key: &SigningKey,
        tag: u32,
    ) -> io::Result<Signed> {
        if actor.len() > 64 || witness.len() > 2048 {
            return Err(invalid("oversized member command"));
        }
        fields(witness, &[1, 2, 3, 4, 5, 6])?;
        let r = &self.replica;
        let body = message(&[
            (1, r.profile()),
            (2, &r.session),
            (3, actor),
            (4, &request),
            (5, witness),
            (12, &message(&[(tag, &[])])),
        ]);
        let raw = Signed(message(&[(1, &body), (2, &key.sign(&body).to_bytes())]));
        self.reserve_seat_command(raw, request)
    }
    pub async fn lobby_stage(&self) -> io::Result<LobbyStage> {
        self.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let r = &self.replica;
        let db = r.lock()?;
        r.require_lobby_genesis(&db)?;
        r.verify_replay(&db)?;
        lobby(&db)?;
        Ok(if at(&db, u64::MAX)?.is_some() {
            LobbyStage::Cancelled
        } else {
            LobbyStage::Open
        })
    }
}
