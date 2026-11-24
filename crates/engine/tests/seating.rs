use rat_race_engine::{ClaimError, LobbyCapacity, LobbySeating, PlayerId, SeatId};

#[test]
fn occupied_seats_are_exclusive_and_remain_in_physical_order() {
    let a = PlayerId::try_from(&b"alpha"[..]).unwrap();
    let b = PlayerId::try_from(&b"bravo"[..]).unwrap();
    for count in [2, 6, 10] {
        let mut table = LobbySeating::new(LobbyCapacity::new(count).unwrap());
        let last = SeatId::new(count).unwrap();
        let first = SeatId::new(1).unwrap();
        assert_eq!(table.claim(&a, last), Ok(()));
        assert_eq!(table.claim(&b, last), Err(ClaimError::SeatUnavailable));
        assert_eq!(table.claim(&a, first), Err(ClaimError::AlreadySeated));
        assert_eq!(table.claim(&a, last), Err(ClaimError::AlreadySeated));
        assert_eq!(table.claim(&b, first), Ok(()));
        assert_eq!(table.occupant(first), Some(&b));
        assert_eq!(table.occupant(last), Some(&a));
        assert_eq!(
            table.seats().map(|(s, _)| s.get()).collect::<Vec<_>>(),
            (1..=count).collect::<Vec<_>>()
        );
    }
}
#[test]
fn stable_identifiers_must_exist_in_this_layout() {
    let mut table = LobbySeating::new(LobbyCapacity::new(2).unwrap());
    let a = PlayerId::try_from(&b"alpha"[..]).unwrap();
    assert!(SeatId::new(0).is_none());
    assert_eq!(
        table.claim(&a, SeatId::new(3).unwrap()),
        Err(ClaimError::UnknownSeat)
    );
}
