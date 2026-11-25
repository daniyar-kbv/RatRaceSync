use super::*;

/// Actor-signed request for the coordinator's scoped private dependency witness.
pub struct LobbyIntent(pub Vec<u8>);

/// Local actor proof, delivered over the authenticated installation's peer channel.
pub struct OwnPreferenceRead(pub Vec<u8>);
impl OwnPreferenceRead {
    pub fn sign(session: &[u8], actor: &[u8], request: [u8; 16], key: &SigningKey) -> Self {
        let body = message(&[
            (1, b"own-lobby-preference/v1"),
            (2, session),
            (3, actor),
            (4, &request),
        ]);
        Self(message(&[(1, &body), (2, &key.sign(&body).to_bytes())]))
    }
}
impl LobbyIntent {
    pub fn sign(
        session: &[u8],
        actor: &[u8],
        request: [u8; 16],
        action: LobbyPreference,
        key: &SigningKey,
    ) -> Self {
        let (tag, value) = operation(action);
        let body = message(&[
            (1, b"setup-guard-request/v1"),
            (2, session),
            (3, actor),
            (4, &request),
            (5, &message(&[(tag, value.as_slice())])),
        ]);
        Self(message(&[(1, &body), (2, &key.sign(&body).to_bytes())]))
    }
}

fn issuer_key(db: &Connection, id: &[u8], index: u64) -> io::Result<[u8; 32]> {
    let creator = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
    if id == creator.node.0 {
        return Ok(creator.key);
    }
    for name in ["first_member", "third_member"] {
        if let Some(m) = store::meta::<JoinedMember>(db, name)?
            && id == m.node.0
            && m.log_id.index <= index
        {
            return Ok(m.key);
        }
    }
    Err(invalid("unknown historical setup coordinator"))
}
impl SeatCommandGuard {
    pub(super) fn preference_material(&self) -> io::Result<&Material> {
        match &self.material {
            Dependencies::Preference(m) => Ok(m),
            _ => Err(invalid("expected player setup")),
        }
    }
    fn witness_message(&self, request: &[u8; 16], m: &Material) -> Vec<u8> {
        // The signed request is known to its actor and trusted replicas. A detached
        // response omits it, including when the untouched dependency has public provenance.
        frame(&[
            b"setup-witness/v1",
            &self.dependency_scope(request, m),
            &m.origin,
            &self.actor_proof,
        ])
    }
    pub(in crate::seating) fn dependency_scope(&self, request: &[u8; 16], m: &Material) -> Vec<u8> {
        let (op, target) = crate::seating::operation(self.action);
        frame(&[
            b"setup-private-dependency/v1",
            &self.profile,
            &self.session,
            &self.actor,
            request,
            &self.node.0,
            &1u64.to_be_bytes(),
            &self.observed,
            &self.layout.to_be_bytes(),
            &(op as u16).to_be_bytes(),
            target.as_slice(),
            &m.setup.to_be_bytes(),
            m.seat.map(SeatId::get).as_slice(),
            &m.seat_revision.to_be_bytes(),
            m.own.dream.map(DreamId::get).as_slice(),
            &[u8::from(m.own.ready)],
            m.ack
                .map(u64::to_be_bytes)
                .as_ref()
                .map_or(&[][..], |n| n.as_slice()),
            &m.revision,
        ])
    }
    pub(in crate::seating) fn verify_witness(
        &mut self,
        db: &Connection,
        index: u64,
        request: &[u8; 16],
        raw: &[u8],
    ) -> io::Result<()> {
        let key = issuer_key(db, &self.observed[8..24], index)?;
        let sig = Signature::from_slice(raw).map_err(io::Error::other)?;
        VerifyingKey::from_bytes(&key)
            .map_err(io::Error::other)?
            .verify_strict(
                &self.witness_message(request, self.preference_material()?),
                &sig,
            )
            .map_err(io::Error::other)?;
        self.witness = Some(sig.to_bytes());
        Ok(())
    }
}
impl LobbyIntent {
    fn authenticate(
        &self,
        r: &Replica,
        peer: ReplicaId,
    ) -> io::Result<(&[u8], [u8; 16], LobbyPreference)> {
        let db = r.lock()?;
        self.authenticate_at(r, &db, peer, u64::MAX)
    }
    pub(in crate::seating) fn authenticate_at(
        &self,
        r: &Replica,
        db: &Connection,
        peer: ReplicaId,
        index: u64,
    ) -> io::Result<(&[u8], [u8; 16], LobbyPreference)> {
        if self.0.len() > 1024 {
            return Err(invalid("oversize setup request"));
        }
        let env = fields(&self.0, &[1, 2])?;
        let body = fields(env[&1], &[1, 2, 3, 4, 5])?;
        let request: [u8; 16] = body[&4].try_into().map_err(io::Error::other)?;
        if body[&1] != b"setup-guard-request/v1"
            || body[&2] != r.session
            || request[6] >> 4 != 4
            || request[8] >> 6 != 2
        {
            return Err(invalid("invalid authenticated setup request"));
        }
        let action = [207, 208]
            .into_iter()
            .find_map(|op| {
                let f = fields(body[&5], &[op]).ok()?;
                let &[n] = f[&op] else { return None };
                parse(op, n).ok()
            })
            .ok_or(invalid("invalid setup input"))?;
        {
            let (node, key) = member(db, body[&3], index)?;
            if node != peer {
                return Err(invalid("incorrect setup requester"));
            }
            VerifyingKey::from_bytes(&key)
                .map_err(io::Error::other)?
                .verify_strict(
                    env[&1],
                    &Signature::from_slice(env[&2]).map_err(io::Error::other)?,
                )
                .map_err(io::Error::other)?;
        }
        Ok((body[&3], request, action))
    }
}
impl GameNode {
    /// Return only the public guard fields and the coordinator's opaque signature.
    /// Peer is the installation authenticated by the transport.
    pub async fn preference_witness(
        &self,
        peer: ReplicaId,
        intent: &LobbyIntent,
        coordinator: &SigningKey,
    ) -> io::Result<Vec<u8>> {
        Ok(self
            .preference_guard(peer, intent, coordinator)
            .await?
            .detached_guard())
    }
    /// Reconstruct and reserve the command on its originating installation.
    pub fn prepare_preference(
        &self,
        intent: &LobbyIntent,
        witness: &[u8],
        key: &SigningKey,
    ) -> io::Result<Signed> {
        if witness.len() > 256 {
            return Err(invalid("oversize setup witness"));
        }
        let r = &self.replica;
        let peer = r.local_node.ok_or(invalid("missing local identity"))?;
        let (actor, request, action) = intent.authenticate(r, peer)?;
        let (tag, value) = operation(action);
        let leaf = message(&[(1, value.as_slice())]);
        fields(witness, &[1, 2, 3, 4, 5, 6])?;
        let mut guard = witness.to_vec();
        wire::field(&mut guard, 7, &intent.0);
        let body = message(&[
            (1, r.profile()),
            (2, &r.session),
            (3, actor),
            (4, &request),
            (5, &guard),
            (12, &message(&[(tag, &leaf)])),
        ]);
        let raw = Signed(message(&[(1, &body), (2, &key.sign(&body).to_bytes())]));
        self.reserve_seat_command(raw, request)
    }

    /// The trusted transport supplies its authenticated peer identity and routes the response
    /// exclusively to that peer. The coordinator signs with its own local installation key.
    pub(crate) async fn preference_guard(
        &self,
        peer: ReplicaId,
        intent: &LobbyIntent,
        coordinator: &SigningKey,
    ) -> io::Result<SeatCommandGuard> {
        let (authenticated_actor, request, action) = intent.authenticate(&self.replica, peer)?;
        let mut g = self
            .seat_guard(authenticated_actor, TableAction::Preference(action))
            .await?;
        let db = self.replica.lock()?;
        let index = u64::from_be_bytes(g.observed[24..].try_into().map_err(io::Error::other)?);
        if !self
            .replica
            .local_node
            .is_some_and(|id| g.observed[8..24] == id.0)
            || issuer_key(&db, &g.observed[8..24], index)? != coordinator.verifying_key().to_bytes()
        {
            return Err(invalid("wrong historical coordinator"));
        }
        g.actor_proof = intent.0.clone();
        g.witness = Some(
            coordinator
                .sign(&g.witness_message(&request, g.preference_material()?))
                .to_bytes(),
        );
        Ok(g)
    }

    /// The authenticated transport supplies the caller identity. There is no subject selector.
    pub async fn own_lobby_preference(
        &self,
        peer: ReplicaId,
        read: &OwnPreferenceRead,
    ) -> io::Result<OwnLobbyPreference> {
        self.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let r = &self.replica;
        if r.lobby_format != Some(lobby::LobbyFormat::DreamReady) {
            return Err(invalid("unsupported preference profile"));
        }
        let db = r.lock()?;
        r.require_lobby_genesis(&db)?;
        r.verify_replay(&db)?;
        lobby(&db)?;
        if read.0.len() > 512 {
            return Err(invalid("oversize private read"));
        }
        let env = fields(&read.0, &[1, 2])?;
        let body = fields(env[&1], &[1, 2, 3, 4])?;
        if body[&1] != b"own-lobby-preference/v1" || body[&2] != r.session || body[&4].len() != 16 {
            return Err(invalid("invalid private read"));
        }
        let (node, key) = member(&db, body[&3], u64::MAX)?;
        if node != peer {
            return Err(invalid("incorrect private reader"));
        }
        VerifyingKey::from_bytes(&key)
            .map_err(io::Error::other)?
            .verify_strict(
                env[&1],
                &Signature::from_slice(env[&2]).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
        effective(&db, body[&3], u64::MAX)
    }
}
