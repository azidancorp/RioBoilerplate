from app.scripts.utils import load_from_html


def test_load_from_html_inlines_json_without_re_sub_escape_processing(tmp_path):
    html_path = tmp_path / "page.html"
    json_path = tmp_path / "data.json"

    json_content = '{"message":"line1\\nline2","emoji":"\\u2603"}'
    json_path.write_text(json_content, encoding="utf-8")
    html_path.write_text(
        (
            "<html><head></head><body>"
            '<script type="application/json" src="data.json" id="seed"></script>'
            "</body></html>"
        ),
        encoding="utf-8",
    )

    output = load_from_html(str(html_path))

    assert 'src="data.json"' not in output
    assert 'id="seed"' in output
    assert json_content in output
