import os
import rio

from app.passwords import get_password_strength as _get_password_strength


def load_markdown(filename: str) -> str:
    """
    Load a Markdown file from the project root directory.

    Args:
        filename: Name of the Markdown file (e.g., "PrivacyPolicy.md")

    Returns:
        The content of the Markdown file, or an error message if not found.
    """
    # Reject path separators and traversal sequences to prevent reading
    # arbitrary files outside the project root.
    if os.sep in filename or "/" in filename or "\\" in filename:
        return "# Content Unavailable\n\nInvalid filename."

    # Get the project root directory
    # This file is at app/app/scripts/utils.py, so go up 3 levels
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))

    md_path = os.path.join(project_root, filename)

    # Resolve symlinks and verify the path stays within the project root.
    resolved = os.path.realpath(md_path)
    if not resolved.startswith(os.path.realpath(project_root) + os.sep):
        return "# Content Unavailable\n\nInvalid filename."

    try:
        with open(resolved, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "# Content Unavailable\n\nThe requested page could not be found."


def get_password_strength(password: str) -> int:
    """Compatibility wrapper around the core password-policy score."""
    return _get_password_strength(password)

def get_password_strength_color(score: int) -> rio.Color:
    """
    Takes a password strength score (0-99) and returns a color between red and
    green.
    """
    score = max(0, min(score, 99))
    red = (99 - score) / 99
    green = score / 99
    return rio.Color.from_rgb(red, green, 0, srgb=True)

def get_password_strength_status(score: int) -> str:
    """
    Returns a descriptive status (very weak, weak, ok, strong, very strong) for a given score.
    """
    if score < 30:
        return 'very weak'
    elif score < 50:
        return 'weak'
    elif score < 70:
        return 'ok'
    elif score < 90:
        return 'strong'
    else:
        return 'very strong'

def load_from_html(html_path):
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    
    # Find and load CSS files
    import re
    import os
    
    # Get the directory of the HTML file
    dir_path = os.path.dirname(html_path)
    
    # Inline Stylesheets that live alongside the HTML asset.
    css_pattern = re.compile(
        r'(<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\'](.*?\.css)["\'][^>]*>)',
        re.IGNORECASE,
    )
    for match in list(css_pattern.finditer(html_content)):
        full_tag, css_ref = match.groups()
        css_path = os.path.normpath(os.path.join(dir_path, css_ref))
        if os.path.exists(css_path):
            with open(css_path, "r", encoding="utf-8") as css_file:
                css_content = css_file.read()
            html_content = html_content.replace(
                full_tag,
                f'<style>\n{css_content}\n</style>',
            )
    
    # Inline JSON script references (e.g. <script type="application/json" src="data.json" id="x">)
    json_refs = re.findall(
        r'<script\s+[^>]*type=["\']application/json["\'][^>]*src=["\'](.*?\.json)["\'][^>]*>\s*</script>',
        html_content,
    )
    for json_ref in json_refs:
        json_path = os.path.normpath(os.path.join(dir_path, json_ref))
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as json_file:
                json_content = json_file.read()
            # Replace src with inline content, preserving other attributes.
            pattern = re.compile(
                r'(<script\s+[^>]*type=["\']application/json["\'][^>]*?)src=["\']'
                + re.escape(json_ref)
                + r'["\']([^>]*>)\s*</script>'
            )
            # Use a callable replacement so backslashes in JSON (e.g. \uXXXX)
            # are inserted literally rather than interpreted as re.sub escapes.
            html_content = pattern.sub(
                lambda match: (
                    f"{match.group(1)}{match.group(2)}\n{json_content}\n</script>"
                ),
                html_content,
            )

    # Inline JS script tags (supports additional attributes like defer, async, type="module").
    script_pattern = re.compile(
        r'(<script\b[^>]*\bsrc=["\'](.*?\.js)["\'][^>]*></script>)',
        re.IGNORECASE,
    )
    for match in list(script_pattern.finditer(html_content)):
        full_tag, js_ref = match.groups()
        js_path = os.path.normpath(os.path.join(dir_path, js_ref))
        if os.path.exists(js_path):
            with open(js_path, "r", encoding="utf-8") as js_file:
                js_content = js_file.read()
            html_content = html_content.replace(
                full_tag,
                f'<script>\n{js_content}\n</script>',
            )
    
    # Inject a baseline responsive guard so embedded webviews can't force
    # horizontal overflow in the Rio page.
    responsive_guard = """
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
html, body {
    width: 100%;
    max-width: 100%;
    margin: 0;
    overflow-x: hidden;
}
*, *::before, *::after {
    box-sizing: border-box;
    max-width: 100%;
}
</style>
"""

    if "<head>" in html_content:
        html_content = html_content.replace("<head>", f"<head>\n{responsive_guard}", 1)
    else:
        html_content = f"{responsive_guard}\n{html_content}"

    return html_content
