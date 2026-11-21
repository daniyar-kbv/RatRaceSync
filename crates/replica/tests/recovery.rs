use rat_race_replica::Replica;
#[test]
fn reopening_requires_the_original_game_identity() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("game.db");
    drop(Replica::open(&file, b"first").unwrap());
    assert!(Replica::open(&file, b"second").is_err());
    assert!(Replica::open(&file, b"first").is_ok());
}

#[test]
fn a_live_replica_excludes_a_second_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("game.db");
    let live = Replica::open(&path, b"one").unwrap();
    assert!(Replica::open(&path, b"one").is_err());
    drop(live);
    assert!(Replica::open(&path, b"one").is_ok());
}
