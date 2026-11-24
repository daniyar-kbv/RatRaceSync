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

#[test]
fn resize_preserves_physical_order_for_every_occupancy_pattern() {
    for n in 2..=10u8 {
        let capacity = LobbyCapacity::new(n).unwrap();
        for mask in 0..(1u16 << n) {
            let mut table = LobbySeating::new(capacity);
            let joined = (mask.count_ones() as usize).max(1);
            for id in capacity
                .ordered_seats()
                .filter(|i| mask & (1 << (i - 1)) != 0)
            {
                table
                    .claim(
                        &PlayerId::try_from(&[id][..]).unwrap(),
                        SeatId::new(id).unwrap(),
                    )
                    .unwrap();
            }
            for target in 2..=10 {
                let order = table.resized_order(LobbyCapacity::new(target).unwrap(), joined);
                if target == n || usize::from(target) < joined {
                    assert!(order.is_none());
                    continue;
                }
                let order: Vec<_> = order.unwrap().into_iter().map(SeatId::get).collect();
                let mut allowed_vacancies = usize::from(target) - mask.count_ones() as usize;
                let expected: Vec<_> = (1..=n.max(target))
                    .filter(|i| {
                        if mask & (1 << (i - 1)) != 0 {
                            true
                        } else if allowed_vacancies > 0 {
                            allowed_vacancies -= 1;
                            true
                        } else {
                            false
                        }
                    })
                    .collect();
                assert_eq!(order, expected);
            }
        }
    }
}
