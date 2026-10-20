from datetime import datetime, timedelta, timezone

from webguard_scope import AuthorizationRegistry, TargetAuthorization


def test_scope_create_and_revoke_emit_audit_events():
    events = []
    registry = AuthorizationRegistry(events.append)
    grant = TargetAuthorization(
        target_id="t1", owner_id="u1", grant_id="g1", allowed_hosts=("example.test",),
        issued_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    registry.register(grant, actor_id="admin")
    assert registry.get("g1") == grant
    assert registry.revoke("g1", actor_id="admin") is True
    assert registry.get("g1") is None
    assert [e.event_type for e in events] == ["scope.created", "scope.revoked"]
    assert all(e.outcome == "changed" for e in events)


def test_updating_a_scope_invalidates_the_old_grant():
    events = []
    registry = AuthorizationRegistry(events.append)
    issued = datetime.now(timezone.utc) - timedelta(seconds=1)
    original = TargetAuthorization(
        target_id="t1", owner_id="u1", grant_id="g1", allowed_hosts=("old.example.test",),
        issued_at=issued,
    )
    revised = TargetAuthorization(
        target_id="t1", owner_id="u1", grant_id="g1", allowed_hosts=("new.example.test",),
        issued_at=issued,
    )
    registry.register(original, actor_id="admin")
    assert registry.is_current(original)
    registry.update(revised, actor_id="admin")
    assert not registry.is_current(original)
    assert registry.is_current(revised)
    assert [event.event_type for event in events] == ["scope.created", "scope.updated"]
