use rat_race_engine::*;

#[test]
fn missing_identifiers_cannot_enter_a_redemption() {
    assert_eq!(PlayerId::try_from(&[][..]), Err(EmptyIdentifier));
    assert_eq!(PositionId::try_from(&[][..]), Err(EmptyIdentifier));
}

#[test]
fn redemption_preserves_opaque_identifiers_exactly() {
    let mut p = portfolio();
    let owner = PlayerId::try_from(&[0xff, 0][..]).unwrap();
    let position_id = PositionId::try_from(&[0, 0xff][..]).unwrap();
    let lot = p.certificates.remove(&position("lot-a")).unwrap();
    p.certificates.insert(position_id.clone(), lot);
    p.owner = owner.clone();
    let intent = RedeemCertificate {
        position: position_id.clone(),
        units: n(1),
    };
    let other = PlayerId::try_from(&[0xfe, 0][..]).unwrap();
    let before = p.clone();
    assert_eq!(
        p.redeem_certificate(&other, &intent),
        Err(RedemptionError::NoOwnedCertificate)
    );
    assert_eq!(p, before);
    let result = p.redeem_certificate(&owner, &intent).unwrap();
    assert_eq!(result.owner, owner);
    assert_eq!(result.position, position_id);
}

fn player(id: &str) -> PlayerId {
    PlayerId::try_from(id.as_bytes()).unwrap()
}
fn position(id: &str) -> PositionId {
    PositionId::try_from(id.as_bytes()).unwrap()
}
fn n(value: i64) -> Integer {
    value.into()
}

fn portfolio() -> Portfolio {
    Portfolio {
        owner: player("a"),
        cash: n(10000),
        monthly_income: n(40),
        certificates: [(
            position("lot-a"),
            CertificateLot {
                source: CertificateSource::Principal5000,
                units: n(2),
            },
        )]
        .into(),
    }
}

fn redeem(p: &mut Portfolio, count: i64) -> Result<Redemption, RedemptionError> {
    p.redeem_certificate(
        &player("a"),
        &RedeemCertificate {
            position: position("lot-a"),
            units: n(count),
        },
    )
}

#[test]
fn partial_redemption_has_exact_original_effects_and_replays_deterministically() {
    let mut a = portfolio();
    let mut b = a.clone();
    let result = redeem(&mut a, 1).unwrap();
    assert_eq!(
        result,
        Redemption {
            owner: player("a"),
            position: position("lot-a"),
            source: CertificateSource::Principal5000,
            principal_per_unit: n(5000),
            units_redeemed: n(1),
            principal_returned: n(5000),
            monthly_income_removed: n(20),
            units: Change {
                before: n(2),
                after: n(1)
            },
            cash: Change {
                before: n(10000),
                after: n(15000)
            },
            lot_monthly_income: Change {
                before: n(40),
                after: n(20)
            },
            player_monthly_income: Change {
                before: n(40),
                after: n(20)
            },
        }
    );
    assert_eq!(a.cash, n(15000));
    assert_eq!(a.monthly_income, n(20));
    assert_eq!(a.certificates[&position("lot-a")].units, n(1));
    assert_eq!(redeem(&mut b, 1).unwrap(), result);
    assert_eq!(a, b);
}

#[test]
fn final_unit_closes_only_its_lot() {
    let mut p = portfolio();
    redeem(&mut p, 1).unwrap();
    redeem(&mut p, 1).unwrap();
    assert_eq!((p.cash.clone(), p.monthly_income.clone()), (n(20000), n(0)));
    assert!(p.certificates.is_empty());
    let before = p.clone();
    assert_eq!(redeem(&mut p, 1), Err(RedemptionError::NoOwnedCertificate));
    assert_eq!(p, before);
}

#[test]
fn bulk_redemption_uses_selected_lots_terms_and_preserves_other_income() {
    let mut p = portfolio();
    let other = p.certificates[&position("lot-a")].clone();
    p.certificates.insert(
        position("lot-b"),
        CertificateLot {
            source: CertificateSource::Principal4000,
            units: n(3),
        },
    );
    p.monthly_income = n(800);
    let result = p
        .redeem_certificate(
            &player("a"),
            &RedeemCertificate {
                position: position("lot-b"),
                units: n(2),
            },
        )
        .unwrap();
    assert_eq!(result.principal_returned, n(8000));
    assert_eq!(p.cash, n(18000));
    assert_eq!(p.monthly_income, n(760));
    assert_eq!(p.certificates[&position("lot-b")].units, n(1));
    assert_eq!(p.certificates[&position("lot-a")], other);
}

#[test]
fn invalid_requests_preserve_all_state() {
    for (actor, lot, units, error) in [
        ("a", "lot-a", 0, RedemptionError::InvalidUnits),
        ("a", "lot-a", -1, RedemptionError::InvalidUnits),
        ("a", "lot-a", 3, RedemptionError::InsufficientUnits),
        ("b", "lot-a", 1, RedemptionError::NoOwnedCertificate),
        (
            "a",
            "non-certificate",
            1,
            RedemptionError::NoOwnedCertificate,
        ),
    ] {
        let mut p = portfolio();
        let before = p.clone();
        assert_eq!(
            p.redeem_certificate(
                &player(actor),
                &RedeemCertificate {
                    position: position(lot),
                    units: n(units)
                }
            ),
            Err(error)
        );
        assert_eq!(p, before);
    }
}

#[test]
fn wide_cash_and_overflow_follow_the_same_decimal_contract() {
    let mut p = portfolio();
    p.cash = "100000000000000000000000000000000000000000000000000"
        .parse()
        .unwrap();
    redeem(&mut p, 1).unwrap();
    assert_eq!(
        p.cash,
        "100000000000000000000000000000000000000000000005000"
            .parse()
            .unwrap()
    );
    p.cash = "9".repeat(128).parse().unwrap();
    let before = p.clone();
    assert_eq!(redeem(&mut p, 1), Err(RedemptionError::ArithmeticRange));
    assert_eq!(p, before);
}

#[test]
fn integer_input_is_canonical_and_bounded() {
    for invalid in [
        "", "-", "+1", "-0", "01", "-01", "1.2", "1e3", " 1", "1_0", "１２",
    ] {
        assert!(invalid.parse::<Integer>().is_err(), "{invalid}");
    }
    assert!("1".repeat(129).parse::<Integer>().is_err());
    assert!(format!("-{}", "9".repeat(128)).parse::<Integer>().is_ok());
    assert_eq!("-1".parse::<Integer>().unwrap(), n(-1));
}
