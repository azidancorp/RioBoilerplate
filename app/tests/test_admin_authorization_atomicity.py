import asyncio
import threading
from pathlib import Path

import pytest

from app.data_models import AppUser, ExpirableVerificationToken
from app.persistence import (
    AdminMutationContext,
    AdminSessionInvalidError,
    Persistence,
)


PASSWORD = "VeryStrongPass!9"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "admin-authorization-atomicity.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_user(
    persistence: Persistence,
    email: str,
    *,
    role: str,
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(
        email=email,
        password=PASSWORD,
    )
    user.role = role
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


async def _admin_context(
    persistence: Persistence,
    actor: AppUser,
) -> AdminMutationContext:
    session = await persistence.create_session(actor.id)
    return AdminMutationContext(auth_token=session.id, client_ip="203.0.113.20")


def _audit_count(
    persistence: Persistence,
    *,
    action: str,
    target_user_id=None,
) -> int:
    return len(
        persistence.list_admin_actions(
            action=action,
            target_user_id=target_user_id,
        )
    )


def test_all_admin_mutations_reject_a_demoted_live_session(temp_db: Persistence):
    async def scenario() -> None:
        actor = await _create_user(
            temp_db,
            "atomic-demoted-actor@example.com",
            role="root",
        )
        target = await _create_user(
            temp_db,
            "atomic-demoted-target@example.com",
            role="user",
        )
        admin_context = await _admin_context(temp_db, actor)
        await temp_db.update_user_role(actor.id, "user")
        role_audits_before = _audit_count(
            temp_db,
            action="role_change",
            target_user_id=target.id,
        )

        with pytest.raises(PermissionError):
            await temp_db.admin_create_user(
                email="blocked-create@example.com",
                password=PASSWORD,
                role="user",
                admin_context=admin_context,
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_update_user_profile(
                target.id,
                admin_context=admin_context,
                email="blocked-email@example.com",
                expected_email=target.email,
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_set_user_active(
                target.id,
                False,
                admin_context=admin_context,
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_issue_password_reset(
                target.id,
                admin_context=admin_context,
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_update_user_role(
                target.id,
                "admin",
                admin_context=admin_context,
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_delete_user(
                target.id,
                admin_context=admin_context,
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_adjust_currency_balance(
                target.id,
                25,
                admin_context=admin_context,
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_set_currency_balance(
                target.id,
                100,
                admin_context=admin_context,
            )

        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.email == target.email
        assert refreshed.is_active is True
        assert refreshed.role == "user"
        assert refreshed.primary_currency_balance == target.primary_currency_balance
        with pytest.raises(KeyError):
            await temp_db.get_user_by_email("blocked-create@example.com")
        assert _audit_count(temp_db, action="user_edit", target_user_id=target.id) == 0
        assert _audit_count(temp_db, action="user_deactivate", target_user_id=target.id) == 0
        assert _audit_count(temp_db, action="password_reset_issued", target_user_id=target.id) == 0
        assert _audit_count(temp_db, action="user_delete", target_user_id=target.id) == 0
        assert _audit_count(temp_db, action="currency_adjust", target_user_id=target.id) == 0
        assert _audit_count(temp_db, action="currency_set", target_user_id=target.id) == 0
        assert _audit_count(
            temp_db,
            action="role_change",
            target_user_id=target.id,
        ) == role_audits_before

    asyncio.run(scenario())


@pytest.mark.parametrize("session_state", ["revoked", "expired"])
def test_admin_currency_rejects_a_non_live_actor_session(
    temp_db: Persistence,
    session_state: str,
):
    async def scenario() -> None:
        actor = await _create_user(
            temp_db,
            f"atomic-{session_state}-actor@example.com",
            role="admin",
        )
        target = await _create_user(
            temp_db,
            f"atomic-{session_state}-target@example.com",
            role="user",
        )
        admin_context = await _admin_context(temp_db, actor)
        if session_state == "revoked":
            await temp_db.invalidate_session(admin_context.auth_token)
        else:
            temp_db.conn.execute(
                "UPDATE user_sessions SET valid_until = 0 WHERE id = ?",
                (temp_db._hash_one_time_token(admin_context.auth_token),),
            )
            temp_db.conn.commit()

        with pytest.raises(
            AdminSessionInvalidError,
            match="session is no longer valid",
        ):
            await temp_db.admin_adjust_currency_balance(
                target.id,
                25,
                admin_context=admin_context,
            )

        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.primary_currency_balance == target.primary_currency_balance
        assert _audit_count(temp_db, action="currency_adjust", target_user_id=target.id) == 0

    asyncio.run(scenario())


def test_demoted_admin_cannot_use_the_currency_self_target_exception(
    temp_db: Persistence,
):
    async def scenario() -> None:
        actor = await _create_user(
            temp_db,
            "atomic-self-currency-actor@example.com",
            role="admin",
        )
        admin_context = await _admin_context(temp_db, actor)
        await temp_db.update_user_role(actor.id, "user")

        with pytest.raises(PermissionError):
            await temp_db.admin_adjust_currency_balance(
                actor.id,
                25,
                admin_context=admin_context,
            )

        refreshed = await temp_db.get_user_by_id(actor.id)
        assert refreshed.primary_currency_balance == actor.primary_currency_balance
        assert _audit_count(temp_db, action="currency_adjust", target_user_id=actor.id) == 0

    asyncio.run(scenario())


def test_admin_mutation_rejects_an_inactive_actor_even_if_the_session_row_remains(
    temp_db: Persistence,
):
    async def scenario() -> None:
        actor = await _create_user(
            temp_db,
            "atomic-inactive-actor@example.com",
            role="admin",
        )
        target = await _create_user(
            temp_db,
            "atomic-inactive-target@example.com",
            role="user",
        )
        admin_context = await _admin_context(temp_db, actor)
        temp_db.conn.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?",
            (str(actor.id),),
        )
        temp_db.conn.commit()

        with pytest.raises(
            AdminSessionInvalidError,
            match="session is no longer valid",
        ):
            await temp_db.admin_adjust_currency_balance(
                target.id,
                25,
                admin_context=admin_context,
            )

        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.primary_currency_balance == target.primary_currency_balance
        assert _audit_count(temp_db, action="currency_adjust", target_user_id=target.id) == 0

    asyncio.run(scenario())


def test_admin_mutations_reject_a_target_promoted_to_a_peer_role(temp_db: Persistence):
    async def scenario() -> None:
        actor = await _create_user(
            temp_db,
            "atomic-peer-actor@example.com",
            role="admin",
        )
        target = await _create_user(
            temp_db,
            "atomic-peer-target@example.com",
            role="user",
        )
        admin_context = await _admin_context(temp_db, actor)
        await temp_db.update_user_role(target.id, "admin")

        with pytest.raises(PermissionError):
            await temp_db.admin_update_user_profile(
                target.id,
                admin_context=admin_context,
                email="blocked-peer@example.com",
                expected_email=target.email,
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_delete_user(
                target.id,
                admin_context=admin_context,
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_adjust_currency_balance(
                target.id,
                25,
                admin_context=admin_context,
            )

        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.email == target.email
        assert refreshed.role == "admin"
        assert refreshed.primary_currency_balance == target.primary_currency_balance

    asyncio.run(scenario())


def test_email_edit_rejects_locked_target_drift_without_purging_tokens(
    temp_db: Persistence,
):
    async def scenario() -> None:
        actor = await _create_user(
            temp_db,
            "atomic-email-root@example.com",
            role="root",
        )
        target = await _create_user(
            temp_db,
            "atomic-email-original@example.com",
            role="user",
        )
        admin_context = await _admin_context(temp_db, actor)
        reset_token = await temp_db.create_reset_token(target.id)

        temp_db.conn.execute(
            "UPDATE users SET email = ? WHERE id = ?",
            ("atomic-email-concurrent@example.com", str(target.id)),
        )
        temp_db.conn.commit()

        with pytest.raises(ValueError, match="email changed while this edit was pending"):
            await temp_db.admin_update_user_profile(
                target.id,
                admin_context=admin_context,
                email="atomic-email-requested@example.com",
                expected_email=target.email,
            )

        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.email == "atomic-email-concurrent@example.com"
        assert (await temp_db.get_user_by_reset_token(reset_token.token)).id == target.id
        assert _audit_count(temp_db, action="user_edit", target_user_id=target.id) == 0

    asyncio.run(scenario())


def test_reset_token_replacement_rolls_back_when_audit_write_fails(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario() -> None:
        actor = await _create_user(
            temp_db,
            "atomic-reset-root@example.com",
            role="root",
        )
        target = await _create_user(
            temp_db,
            "atomic-reset-target@example.com",
            role="user",
        )
        admin_context = await _admin_context(temp_db, actor)
        previous_token = await temp_db.create_reset_token(target.id)
        original_record = temp_db.record_admin_action

        def fail_reset_audit(**kwargs) -> None:
            if kwargs.get("action") == "password_reset_issued":
                raise RuntimeError("forced reset audit failure")
            original_record(**kwargs)

        monkeypatch.setattr(temp_db, "record_admin_action", fail_reset_audit)
        with pytest.raises(RuntimeError, match="forced reset audit failure"):
            await temp_db.admin_issue_password_reset(
                target.id,
                admin_context=admin_context,
            )

        assert (await temp_db.get_user_by_reset_token(previous_token.token)).id == target.id
        assert _audit_count(
            temp_db,
            action="password_reset_issued",
            target_user_id=target.id,
        ) == 0

    asyncio.run(scenario())


def test_reset_issuance_returns_the_recipient_captured_under_the_write_lock(
    temp_db: Persistence,
):
    async def scenario() -> None:
        actor = await _create_user(
            temp_db,
            "atomic-reset-recipient-root@example.com",
            role="root",
        )
        target = await _create_user(
            temp_db,
            "atomic-reset-recipient-old@example.com",
            role="user",
        )
        admin_context = await _admin_context(temp_db, actor)
        updated = await temp_db.admin_update_user_profile(
            target.id,
            admin_context=admin_context,
            email="atomic-reset-recipient-new@example.com",
            expected_email=target.email,
        )

        issuance = await temp_db.admin_issue_password_reset(
            target.id,
            admin_context=admin_context,
        )

        assert isinstance(issuance, ExpirableVerificationToken)
        assert issuance.recipient_email == updated.email
        assert (await temp_db.get_user_by_reset_token(issuance.token)).id == target.id
        actions = temp_db.list_admin_actions(
            action="password_reset_issued",
            target_user_id=target.id,
        )
        assert len(actions) == 1
        assert actions[0]["target_label"] == updated.email

    asyncio.run(scenario())


def test_demotion_committing_first_blocks_the_waiting_admin_mutation(
    temp_db: Persistence,
):
    actor, target, admin_context = asyncio.run(_setup_currency_race(temp_db))
    revoker = Persistence(db_path=temp_db.db_path)
    begin_attempted = threading.Event()
    outcome: dict[str, object] = {}

    revoker.conn.execute("BEGIN IMMEDIATE")
    revoker.conn.execute(
        "UPDATE users SET role = 'user' WHERE id = ?",
        (str(actor.id),),
    )
    revoker.conn.execute(
        "UPDATE user_sessions SET role = 'user' WHERE user_id = ?",
        (str(actor.id),),
    )

    def mutate() -> None:
        persistence = Persistence(db_path=temp_db.db_path)

        def trace(statement: str) -> None:
            if statement.strip().upper().startswith("BEGIN IMMEDIATE"):
                begin_attempted.set()

        persistence.conn.set_trace_callback(trace)
        try:
            outcome["entry"] = asyncio.run(
                persistence.admin_adjust_currency_balance(
                    target.id,
                    25,
                    admin_context=admin_context,
                )
            )
        except BaseException as exc:
            outcome["error"] = exc
        finally:
            outcome["in_transaction"] = persistence.conn.in_transaction
            persistence.close()

    thread = threading.Thread(target=mutate)
    thread.start()
    assert begin_attempted.wait(timeout=10) is True
    revoker.conn.commit()
    thread.join(timeout=10)
    revoker.close()

    assert thread.is_alive() is False
    assert isinstance(outcome.get("error"), PermissionError)
    assert "entry" not in outcome
    assert outcome["in_transaction"] is False
    refreshed = asyncio.run(temp_db.get_user_by_id(target.id))
    assert refreshed.primary_currency_balance == target.primary_currency_balance


def test_admin_mutation_committing_first_precedes_the_waiting_demotion(
    temp_db: Persistence,
):
    actor, target, admin_context = asyncio.run(_setup_currency_race(temp_db))
    target_read_reached = threading.Event()
    allow_mutation = threading.Event()
    demotion_begin_attempted = threading.Event()
    outcome: dict[str, object] = {}

    def mutate() -> None:
        persistence = Persistence(db_path=temp_db.db_path)

        def trace(statement: str) -> None:
            normalized = " ".join(statement.upper().split())
            if (
                "SELECT EMAIL, USERNAME, ROLE, IS_ACTIVE, AUTH_PROVIDER" in normalized
                and str(target.id).upper() in normalized
                and not target_read_reached.is_set()
            ):
                target_read_reached.set()
                allow_mutation.wait(timeout=10)

        persistence.conn.set_trace_callback(trace)
        try:
            outcome["entry"] = asyncio.run(
                persistence.admin_adjust_currency_balance(
                    target.id,
                    25,
                    admin_context=admin_context,
                )
            )
        except BaseException as exc:
            outcome["mutation_error"] = exc
        finally:
            persistence.close()

    def demote() -> None:
        persistence = Persistence(db_path=temp_db.db_path)

        def trace(statement: str) -> None:
            if statement.strip().upper().startswith("BEGIN IMMEDIATE"):
                demotion_begin_attempted.set()

        persistence.conn.set_trace_callback(trace)
        try:
            asyncio.run(persistence.update_user_role(actor.id, "user"))
        except BaseException as exc:
            outcome["demotion_error"] = exc
        finally:
            persistence.close()

    mutation_thread = threading.Thread(target=mutate)
    mutation_thread.start()
    assert target_read_reached.wait(timeout=10) is True
    demotion_thread = threading.Thread(target=demote)
    demotion_thread.start()
    assert demotion_begin_attempted.wait(timeout=10) is True
    allow_mutation.set()
    mutation_thread.join(timeout=10)
    demotion_thread.join(timeout=10)

    assert mutation_thread.is_alive() is False
    assert demotion_thread.is_alive() is False
    assert "mutation_error" not in outcome
    assert "demotion_error" not in outcome
    refreshed_target = asyncio.run(temp_db.get_user_by_id(target.id))
    refreshed_actor = asyncio.run(temp_db.get_user_by_id(actor.id))
    assert refreshed_target.primary_currency_balance == target.primary_currency_balance + 25
    assert refreshed_actor.role == "user"
    actions = temp_db.list_admin_actions(
        action="currency_adjust",
        target_user_id=target.id,
    )
    assert len(actions) == 1
    assert actions[0]["actor_user_id"] == actor.id
    assert actions[0]["actor_role"] == "admin"


async def _setup_currency_race(
    persistence: Persistence,
) -> tuple[AppUser, AppUser, AdminMutationContext]:
    actor = await _create_user(
        persistence,
        "atomic-race-admin@example.com",
        role="admin",
    )
    target = await _create_user(
        persistence,
        "atomic-race-target@example.com",
        role="user",
    )
    return actor, target, await _admin_context(persistence, actor)
