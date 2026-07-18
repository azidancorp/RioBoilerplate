"""Static checks on the documented production HTTP configuration.

Recovery and OAuth flows carry secrets in URL query strings, so the deployment
guide's Nginx access-log sample must never log query strings or referrers, and
its redirects must not copy query arguments into logged Location headers.
These tests pin the repository-owned policy; live `nginx -t` plus access-log,
error-log, and upstream sentinel validation must still happen on the host.
"""

import re
from pathlib import Path

DEPLOYMENT_DOC = Path(__file__).resolve().parents[2] / "DEPLOYMENT_INSTRUCTIONS.md"

FORBIDDEN_LOG_VARIABLES = (
    r"\$request\b",
    r"\$request_uri\b",
    r"\$args\b",
    r"\$query_string\b",
    r"\$http_referer\b",
)


def _nginx_config_without_comments() -> str:
    text = DEPLOYMENT_DOC.read_text(encoding="utf-8")
    match = re.search(r"```nginx\n(.*?)```", text, re.DOTALL)
    assert match is not None, "Nginx sample block missing from deployment doc"
    lines = (
        line.split("#", 1)[0]
        for line in match.group(1).splitlines()
    )
    return "\n".join(lines)


def _nginx_server_blocks(config: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    depth = 0

    for line in config.splitlines():
        if not current:
            if re.fullmatch(r"\s*server\s*\{\s*", line):
                current = [line]
                depth = 1
            continue

        current.append(line)
        depth += line.count("{") - line.count("}")
        if depth == 0:
            blocks.append("\n".join(current))
            current = []

    assert not current, "Unclosed server block in Nginx sample"
    return blocks


def test_documented_nginx_logging_is_queryless() -> None:
    config = _nginx_config_without_comments()
    server_blocks = _nginx_server_blocks(config)

    assert "log_format queryless" in config
    for pattern in FORBIDDEN_LOG_VARIABLES:
        assert re.search(pattern, config) is None, pattern

    assert len(server_blocks) == 3
    for block in server_blocks:
        access_logs = re.findall(r"^\s*access_log\s+([^;]+);", block, re.MULTILINE)
        assert access_logs == ["/var/log/nginx/access.log queryless"]


def test_documented_redirects_drop_query_arguments() -> None:
    config = _nginx_config_without_comments()
    server_blocks = _nginx_server_blocks(config)

    redirect_blocks = [
        block
        for block in server_blocks
        if re.search(r"\breturn\s+30[12378]\s+", block)
    ]
    assert len(redirect_blocks) == 2
    for block in redirect_blocks:
        redirect_targets = re.findall(r"return\s+30[12378]\s+(\S+);", block)
        assert redirect_targets
        assert all(target.endswith("$uri") for target in redirect_targets)
        assert 'add_header Cache-Control "no-store" always;' in block
        assert 'add_header Referrer-Policy "no-referrer" always;' in block


def test_documented_rio_release_commands_pin_quiet_mode() -> None:
    text = DEPLOYMENT_DOC.read_text(encoding="utf-8")
    smoke_command = '../venv/bin/rio run --port "$APP_PORT" --release --quiet'
    service_commands = re.findall(r"^ExecStart=.*rio run.*$", text, re.MULTILINE)

    assert smoke_command in text
    assert len(service_commands) == 1
    assert "--release" in service_commands[0]
    assert "--quiet" in service_commands[0]
