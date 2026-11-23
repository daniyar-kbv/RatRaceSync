use super::*;
use std::{
    sync::mpsc::{RecvTimeoutError, sync_channel},
    time::Duration,
};

impl Replica {
    pub(crate) fn notify_sealer(&self) {
        if let Ok(sender) = self.seal_wake.lock()
            && let Some(sender) = sender.as_ref()
        {
            let _ = sender.try_send(());
        }
    }

    fn seal_applied_batch(&self, key: &SigningKey) -> io::Result<bool> {
        let mut db = self.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        let high = history::boundary(&tx)?;
        history::schema(&tx)?;
        let first = history::cursor(&tx)?;
        if first > high.index {
            return Ok(false);
        }
        self.require_lobby_genesis(&tx)?;
        let creator = store::meta::<Creator>(&tx, "creator")?.ok_or(invalid("missing creator"))?;
        if &creator.key != key.verifying_key().as_bytes() || self.local_node != Some(creator.node) {
            return Err(invalid("ineligible historical signer"));
        }
        self.verify_replay(&tx)?;
        let last = first.saturating_add(15).min(high.index);
        for index in first..=last {
            if history::joined_at(&tx, index)?.is_some() {
                tx.commit().map_err(io::Error::other)?;
                return Ok(false);
            }
            history::seal(self, &tx, index, key)?;
        }
        tx.commit().map_err(io::Error::other)?;
        Ok(last < high.index)
    }
}

pub(crate) struct SealWorker {
    stopped: Arc<std::sync::atomic::AtomicBool>,
    wake: std::sync::mpsc::SyncSender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for SealWorker {
    fn drop(&mut self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Release);
        let _ = self.wake.try_send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl GameNode {
    /// Keep signing material in memory only while this creator is running.
    /// Failed or interrupted batches leave the previously sealed prefix intact.
    pub(crate) fn enable_sealer(self: &Arc<Self>, key: &SigningKey) -> io::Result<()> {
        let mut wake = self
            .replica
            .seal_wake
            .lock()
            .map_err(|_| invalid("sealer lock poisoned"))?;
        if wake.is_some() {
            return Ok(());
        }
        let (tx, rx) = sync_channel(1);
        let mut worker = self
            .sealer
            .lock()
            .map_err(|_| invalid("sealer owner lock poisoned"))?;
        let replica = self.replica.clone();
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = stopped.clone();
        let key = key.clone();
        let thread = std::thread::Builder::new()
            .name("lobby-history".into())
            .spawn(move || {
                let mut pending = true;
                loop {
                    if stop.load(std::sync::atomic::Ordering::Acquire) {
                        return;
                    }
                    let result = if pending {
                        replica.seal_applied_batch(&key)
                    } else {
                        Ok(false)
                    };
                    if matches!(result, Ok(true)) {
                        continue;
                    }
                    pending = result.is_err();
                    match rx.recv_timeout(Duration::from_secs(2)) {
                        Ok(()) => pending = true,
                        Err(RecvTimeoutError::Timeout) => (),
                        Err(RecvTimeoutError::Disconnected) => return,
                    }
                }
            })?;
        *worker = Some(SealWorker {
            stopped,
            wake: tx.clone(),
            thread: Some(thread),
        });
        *wake = Some(tx);
        Ok(())
    }
}
