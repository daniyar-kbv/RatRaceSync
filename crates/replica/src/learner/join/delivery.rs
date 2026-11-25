use super::*;

/// Adapter for the authenticated peer exchanges used to join a two-voter lobby.
/// A stale verified prefix is reported by the leader as `WouldBlock`.
#[allow(async_fn_in_trait)]
pub trait ThirdJoinTransport {
    async fn recover(&mut self, request: Vec<u8>) -> io::Result<Vec<u8>>;
    async fn confirm(&mut self, draft: Vec<u8>, route: Vec<u8>) -> io::Result<[Vec<u8>; 2]>;
    async fn submit(&mut self, original: Vec<u8>) -> io::Result<JoinResult>;
    async fn history(&mut self, request: VotingHistoryRequest) -> io::Result<Vec<u8>>;
}
impl InstallationCatalog {
    /// Deliver the installation's durable Join, checking the leader's reply against
    /// local application. Retry the saved proposal first after a lost response.
    pub async fn join_third_player(
        &mut self,
        learner: &mut Learner,
        key: &SigningKey,
        request: [u8; 16],
        profile_complete: bool,
        network: &mut impl ThirdJoinTransport,
    ) -> io::Result<JoinDelivery> {
        self.reserved_learner(learner)?;
        let admission = learner.admission(key)?;
        let previous = {
            let r = &learner.node.replica;
            let db = r.lock()?;
            if third::local_route(r, &db)?.is_none() {
                return Err(invalid("missing third recovery route"));
            }
            for name in ["local_join", "third_proposal"] {
                if let Some(raw) = store::meta::<Vec<u8>>(&db, name)? {
                    let intent = parse(r, &raw)?;
                    if intent.admission != admission
                        || (intent.request != request
                            && r.lobby_format != Some(lobby::LobbyFormat::Resizable))
                    {
                        return Err(invalid("another Join owns this reservation"));
                    }
                }
            }
            match store::meta::<Vec<u8>>(&db, "third_proposal")? {
                Some(raw) if parse(r, &raw)?.request == request => Some(raw),
                _ => None,
            }
        };
        if let Some(raw) = previous {
            let checked = self.pending_join(learner)?;
            if checked != raw {
                return Err(invalid("pending Join changed"));
            }
            match network.submit(raw.clone()).await {
                Ok(reply) => {
                    return self
                        .finish_join(learner, key, &raw, reply, async |q| {
                            network.history(q).await
                        })
                        .await;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                Err(e) => return Err(e),
            }
        }
        self.recover_learner(learner, key, async |q| network.recover(q).await)
            .await?;
        let raw = self
            .prepare_third_join(
                learner,
                key,
                request,
                profile_complete,
                async |draft, route| network.confirm(draft, route).await,
            )
            .await?;
        let reply = network.submit(raw.clone()).await?;
        self.finish_join(learner, key, &raw, reply, async |q| {
            network.history(q).await
        })
        .await
    }
}
