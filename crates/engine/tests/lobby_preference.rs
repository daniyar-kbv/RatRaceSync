use rat_race_engine::{DreamId, LobbyPreference, PreferenceTransition, SeatId};
#[test]
fn only_ready_with_an_existing_equal_acknowledgment_can_be_unchanged() {
    let dream = DreamId::new(2).unwrap();
    let seat = SeatId::new(1);
    let off = LobbyPreference::Ready(false);
    assert_eq!(
        off.transition(seat, Some(dream), None),
        Some(PreferenceTransition::Acknowledge(false))
    );
    assert_eq!(
        off.transition(seat, Some(dream), Some(false)),
        Some(PreferenceTransition::Unchanged)
    );
    assert_eq!(
        off.transition(seat, Some(dream), Some(true)),
        Some(PreferenceTransition::Acknowledge(false))
    );
    assert_eq!(off.transition(None, Some(dream), Some(false)), None);
    assert_eq!(off.transition(seat, None, Some(false)), None);
    assert_eq!(
        LobbyPreference::Dream(dream).transition(None, Some(dream), None),
        None
    );
    assert_eq!(
        LobbyPreference::Dream(dream).transition(None, None, None),
        Some(PreferenceTransition::Select(dream))
    );
}
