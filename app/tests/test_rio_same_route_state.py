import asyncio
from pathlib import Path

import pytest
import rio
from rio import data_models
from rio.app_server import TestingServer as _RioTestingServer
from rio.routing import BUILD_FUNCTION_TO_PAGE
from rio.transports import MessageRecorderTransport
from starlette.datastructures import Headers

from app.data_models import AppUser
from app.pages.app_page.enable_mfa import EnableMFA
from app.persistence import Persistence
from app.persistence_social import (
    OAUTH_MFA_ENABLE_PURPOSE,
    oauth_reauth_approval_prefix,
)


@rio.page(url_segment="oauth-scrub-probe")
class _OAuthScrubProbe(rio.Component):
    captured_token: str = ""
    populate_count: int = 0
    initialized_after_scrub: bool = False

    # The MFA lifecycle pages populate synchronously and fall through after
    # scrubbing the URL, because Rio does not re-run a synchronous population
    # after same-route replace navigation. The probe mirrors that structure.
    @rio.event.on_populate
    def on_populate(self) -> None:
        self.populate_count += 1
        token = str(self.session.active_page_url.query.get("token", ""))
        if token:
            self.captured_token = token
            self.session.navigate_to("/oauth-scrub-probe", replace=True)
        self.initialized_after_scrub = True

    def build(self) -> rio.Component:
        return rio.Text(self.captured_token)


async def _create_probe_session(app: rio.App, url: str):
    server = _RioTestingServer(
        app,
        debug_mode=False,
        running_in_window=False,
    )
    refresh_event = asyncio.Event()
    transport: MessageRecorderTransport

    def process_message(message) -> None:
        if message.get("method") == "updateComponentStates":
            refresh_event.set()
        if "id" in message:
            transport.queue_response(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": None,
                }
            )

    transport = MessageRecorderTransport(process_sent_message=process_message)
    session = await server.create_session(
        initial_message=data_models.InitialClientMessage.from_defaults(
            url=url,
            user_settings={},
        ),
        transport=transport,
        client_ip="localhost",
        client_port=12345,
        http_headers=Headers(),
        cookies={},
    )
    await asyncio.wait_for(refresh_event.wait(), timeout=5)
    return session


def test_same_route_replace_preserves_server_component_state() -> None:
    async def scenario() -> None:
        app = rio.App(
            name="OAuth scrub probe",
            pages=[BUILD_FUNCTION_TO_PAGE[_OAuthScrubProbe]],
        )
        session = await _create_probe_session(
            app,
            "http://unit.test/oauth-scrub-probe?token=approval-token",
        )

        try:
            for _ in range(100):
                probes = [
                    component
                    for component in session._weak_components_by_id.values()
                    if isinstance(component, _OAuthScrubProbe)
                ]
                if (
                    probes
                    and probes[0].initialized_after_scrub
                    and "token" not in session.active_page_url.query
                ):
                    break
                await asyncio.sleep(0.01)
            else:
                raise AssertionError("same-route URL scrub did not finish")

            probe = probes[0]
            assert probe.captured_token == "approval-token"
            # Rio performs no second population pass for a synchronous
            # handler; a single fall-through pass must complete setup.
            assert probe.populate_count == 1
            assert probe.initialized_after_scrub is True
            assert str(session.active_page_url) == (
                "http://unit.test/oauth-scrub-probe"
            )
        finally:
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


def test_enable_mfa_page_generates_secret_in_scrub_pass(tmp_path: Path) -> None:
    """The real EnableMFA page must hold the approval, a candidate secret,
    and QR bytes after the callback URL is scrubbed — in one populate pass."""

    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / "enable-mfa-scrub.db")
        try:
            user = AppUser.create_social_user(
                email="google-scrub@example.com",
                provider="google",
                provider_user_id="sub-google-scrub",
                is_verified=True,
            )
            await persistence._create_user_unchecked(user)
            user = await persistence.get_user_by_id(user.id)
            assert user.password_hash is None
            user_session = await persistence.create_session(user.id)

            challenge = await persistence.create_oauth_reauth_challenge(
                user_id=user.id,
                provider="google",
                purpose=OAUTH_MFA_ENABLE_PURPOSE,
                auth_token=user_session.id,
            )
            approval = await persistence.exchange_oauth_reauth_challenge(
                challenge_token=challenge,
                provider="google",
                purpose=OAUTH_MFA_ENABLE_PURPOSE,
                provider_user_id=str(user.auth_provider_id),
            )

            app = rio.App(
                name="EnableMFA scrub probe",
                pages=[
                    rio.ComponentPage(
                        name="App",
                        url_segment="app",
                        build=rio.PageView,
                        children=[BUILD_FUNCTION_TO_PAGE[EnableMFA]],
                    )
                ],
                default_attachments=[persistence, user_session],
            )
            session = await _create_probe_session(
                app,
                "http://unit.test/app/enable-mfa"
                f"?enable_mfa_oauth_token={approval}",
            )

            try:
                for _ in range(100):
                    pages = [
                        component
                        for component in session._weak_components_by_id.values()
                        if isinstance(component, EnableMFA)
                    ]
                    if (
                        pages
                        and "enable_mfa_oauth_token"
                        not in session.active_page_url.query
                    ):
                        break
                    await asyncio.sleep(0.01)
                else:
                    raise AssertionError("callback URL scrub did not finish")

                page = pages[0]
                assert page.auth_provider == "google"
                assert page.oauth_approval_token == approval
                assert page.temporary_two_factor_secret
                assert page.qr_code_image_bytes
                assert page.error_message == ""
                assert persistence.conn.execute(
                    """
                    SELECT 1
                    FROM oauth_login_handoffs
                    WHERE token_hash = ?
                    """,
                    (persistence._hash_one_time_token(approval),),
                ).fetchone() == (1,)
                assert str(session.active_page_url) == (
                    "http://unit.test/app/enable-mfa"
                )
            finally:
                await session._close(close_remote_session=False)
        finally:
            persistence.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("approval_case", ["forged", "expired", "wrong-session"])
def test_enable_mfa_page_rejects_unusable_approval_before_setup(
    tmp_path: Path,
    approval_case: str,
) -> None:
    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / f"{approval_case}.db")
        try:
            user = AppUser.create_social_user(
                email=f"google-{approval_case}@example.com",
                provider="google",
                provider_user_id=f"sub-google-{approval_case}",
                is_verified=True,
            )
            await persistence._create_user_unchecked(user)
            user = await persistence.get_user_by_id(user.id)
            assert user.password_hash is None
            bound_session = await persistence.create_session(user.id)
            page_session = bound_session

            if approval_case == "forged":
                approval = (
                    oauth_reauth_approval_prefix(OAUTH_MFA_ENABLE_PURPOSE)
                    + "A" * 64
                )
            else:
                challenge = await persistence.create_oauth_reauth_challenge(
                    user_id=user.id,
                    provider="google",
                    purpose=OAUTH_MFA_ENABLE_PURPOSE,
                    auth_token=bound_session.id,
                )
                approval = await persistence.exchange_oauth_reauth_challenge(
                    challenge_token=challenge,
                    provider="google",
                    purpose=OAUTH_MFA_ENABLE_PURPOSE,
                    provider_user_id=str(user.auth_provider_id),
                )
                if approval_case == "expired":
                    persistence.conn.execute(
                        """
                        UPDATE oauth_login_handoffs
                        SET valid_until = 0
                        WHERE token_hash = ?
                        """,
                        (persistence._hash_one_time_token(approval),),
                    )
                    persistence.conn.commit()
                else:
                    page_session = await persistence.create_session(user.id)

            app = rio.App(
                name="EnableMFA invalid approval probe",
                pages=[
                    rio.ComponentPage(
                        name="App",
                        url_segment="app",
                        build=rio.PageView,
                        children=[BUILD_FUNCTION_TO_PAGE[EnableMFA]],
                    )
                ],
                default_attachments=[persistence, page_session],
            )
            session = await _create_probe_session(
                app,
                "http://unit.test/app/enable-mfa"
                f"?enable_mfa_oauth_token={approval}",
            )

            try:
                for _ in range(100):
                    pages = [
                        component
                        for component in session._weak_components_by_id.values()
                        if isinstance(component, EnableMFA)
                    ]
                    if (
                        pages
                        and "enable_mfa_oauth_token"
                        not in session.active_page_url.query
                    ):
                        break
                    await asyncio.sleep(0.01)
                else:
                    raise AssertionError("invalid callback URL scrub did not finish")

                page = pages[0]
                assert page.auth_provider == "google"
                assert page.oauth_approval_token == ""
                assert page.oauth_status == ""
                assert page.password == ""
                assert page.verification_code == ""
                assert page.temporary_two_factor_secret == ""
                assert page.qr_code_image_bytes is None
                assert "Verify with Google again" in page.error_message
                assert str(session.active_page_url) == (
                    "http://unit.test/app/enable-mfa"
                )
            finally:
                await session._close(close_remote_session=False)
        finally:
            persistence.close()

    asyncio.run(scenario())
