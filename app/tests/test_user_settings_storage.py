from app.data_models import UserSettings


def test_auth_token_is_the_only_http_only_user_setting():
    assert UserSettings._rio_attrs_to_save_as_cookies_ == {"auth_token"}


def test_http_only_token_is_loaded_from_cookie_not_local_storage():
    settings = UserSettings._from_json(
        localstorage_sections={
            "": {
                "auth_token": "javascript-readable-token",
                "two_factor_enabled": True,
            }
        },
        cookie_sections={"": {"auth_token": "http-only-token"}},
        defaults=UserSettings(auth_token=""),
    )

    assert settings.auth_token == "http-only-token"
    assert settings.two_factor_enabled is True


def test_old_local_storage_token_is_not_treated_as_http_only_token():
    settings = UserSettings._from_json(
        localstorage_sections={"": {"auth_token": "old-local-token"}},
        cookie_sections={},
        defaults=UserSettings(auth_token=""),
    )

    assert settings.auth_token == ""
