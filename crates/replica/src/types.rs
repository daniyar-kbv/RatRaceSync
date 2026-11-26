use super::{io, store};
use openraft::entry::RaftPayload;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
pub struct ReplicaId(pub [u8; 16]);
impl fmt::Display for ReplicaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
openraft::declare_raft_types!(pub Types: D=Signed,R=Reply,NodeId=ReplicaId,Node=(),Payload=Source);
pub type LogId = openraft::alias::LogIdOf<Types>;
pub type Entry = <Types as openraft::RaftTypeConfig>::Entry;
pub type Vote = openraft::alias::VoteOf<Types>;
pub type Members = openraft::membership::Membership<ReplicaId, ()>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signed(pub Vec<u8>);
impl fmt::Display for Signed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signed command")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Protocol,
    Receipt(Vec<u8>),
    RequestIdConflict,
    AlreadyCurrent,
}
/// Original payload bytes travel with the typed Raft entry, including genesis membership.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Source {
    pub(crate) bytes: Vec<u8>,
    members: Option<Members>,
}
impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "raft payload")
    }
}
impl RaftPayload for Source {
    type D = Signed;
    type Membership = Members;
    fn blank() -> Self {
        Self {
            bytes: vec![0],
            members: None,
        }
    }
    fn with_normal(self, cmd: Signed) -> Self {
        let members = self.members;
        let mut bytes = vec![1];
        bytes.extend(cmd.0);
        let source = Self {
            bytes,
            members: None,
        };
        if let Some(m) = members {
            source.with_membership(m)
        } else {
            source
        }
    }
    fn with_membership(self, m: Members) -> Self {
        let mut bytes = vec![if self.bytes.first() == Some(&1) { 3 } else { 2 }];
        bytes.extend(store::encode(&m).expect("integer membership is serializable"));
        bytes.extend(self.bytes);
        Self {
            bytes,
            members: Some(m),
        }
    }
    fn get_membership(&self) -> Option<Members> {
        self.members.clone()
    }
}
impl Source {
    pub(crate) fn retained_membership(bytes: Vec<u8>, members: Members) -> Self {
        Self {
            bytes,
            members: Some(members),
        }
    }
    pub(crate) fn leave_source(&self) -> io::Result<Option<&[u8]>> {
        Ok(self
            .combined_command()?
            .filter(|raw| crate::seating::departure::is_source(raw)))
    }
    pub(crate) fn registration(route: &[u8]) -> Self {
        Self::blank().with_normal(Signed(crate::wire::message(&[
            (1, b"RatRaceSync/learner/registration/v1"),
            (2, route),
        ])))
    }
    pub(crate) fn registration_source(&self) -> io::Result<Option<&[u8]>> {
        Ok(self
            .combined_command()?
            .and_then(|raw| crate::wire::fields(raw, &[1, 2]).ok())
            .filter(|f| f[&1] == b"RatRaceSync/learner/registration/v1")
            .map(|f| f[&2]))
    }
    pub(crate) fn join_command(&self) -> io::Result<Option<&[u8]>> {
        if self.registration_source()?.is_some() {
            return Ok(None);
        }
        Ok(self
            .combined_command()?
            .filter(|raw| !crate::seating::departure::is_source(raw)))
    }
    fn combined_command(&self) -> io::Result<Option<&[u8]>> {
        if self.bytes.first() != Some(&3) {
            return Ok(None);
        }
        let m = self
            .members
            .as_ref()
            .ok_or(super::invalid("missing combined membership"))?;
        let prefix = store::encode(m)?;
        let raw = self.bytes[1..]
            .strip_prefix(prefix.as_slice())
            .and_then(|v| v.strip_prefix(&[1]))
            .filter(|v| !v.is_empty())
            .ok_or(super::invalid("invalid combined source"))?;
        Ok(Some(raw))
    }
    pub(crate) fn check_members(&self) -> io::Result<Option<Members>> {
        if self.combined_command()?.is_some() {
            return Ok(self.members.clone());
        }
        if let Some(m) = self.members.as_ref() {
            let expected = Self::blank().with_membership(m.clone());
            if expected.bytes != self.bytes {
                return Err(super::invalid("unexpected membership payload"));
            }
        }
        Ok(self.members.clone())
    }
}
pub(crate) fn log_key(k: LogId) -> Vec<u8> {
    [
        k.leader_id.term.to_be_bytes().as_slice(),
        &k.leader_id.node_id.0,
        &k.index.to_be_bytes(),
    ]
    .concat()
}
