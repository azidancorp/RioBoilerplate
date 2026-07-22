# Crawler Bootstrap Breakage from Embedded Webview Scripts

Date: 2026-07-11

Status: **confirmed on the public home page; not yet fixed.**

Severity: **Medium.** Crawler-mode rendering is currently broken on `/`. The
same encoding mistake is also a top-document injection primitive if
attacker-controlled text ever reaches crawler-visible component state, but the
current triggering content is a fixed repository file and no active
user-input path was found.

## Executive Summary

The home page includes a prototype `rio.Webview` whose HTML contains a
`<script>...</script>` element. For ordinary browser sessions, Rio sends that
Webview state over a WebSocket and the prototype works as intended. For a
recognized crawler, Rio instead serializes the initial component messages with
plain `json.dumps()` and inserts the result directly into an inline script in
the top-level HTML document.

The Webview's literal `</script>` survives JSON serialization. HTML parsing
happens before JavaScript parsing, and an HTML parser closes the top-level
script as soon as it encounters that sequence, even though JavaScript would
have considered it part of a quoted JSON string. This truncates
`globalThis.initialMessages` before `root_component_id`, leaving Rio without a
valid initial component tree.

The current trigger is application code, but the underlying defect is in Rio
0.12.2's HTML embedding boundary:

```text
JSPages/test.html + test.js
        |
        v
load_from_html() creates self-contained HTML with <script>...</script>
        |
        v
rio.Webview(content=<the HTML string>)
        |
        v
Rio serializes the component state as JSON
        |
        v  crawler requests only
globalThis.initialMessages = <JSON> inside a top-level <script>
        |
        v
the Webview's </script> closes the top-level script prematurely
```

## Reconciliation of the Two Analyses

Both investigations agree on the observed failure, affected route, parser
mechanism, present rendering impact, and absence of a current user-controlled
source. The following refinements matter when choosing a fix:

- Saying that `json.dumps()` does not escape the forward slash describes one
  way the terminator remains literal, but the broader defect is that ordinary
  JSON output is being inserted into HTML without script-safe encoding.
  Escaping `<` at that boundary prevents all HTML tags from beginning and is
  the preferred general treatment.
- `root_component_id` is a useful landmark showing that the message was cut
  short. The problem is not merely that this field is missing: the entire
  JavaScript assignment ends inside a quoted string and is invalid.
- Rewriting or HTML-escaping `</script>` inside `load_from_html()` would mutate
  the value later consumed as real iframe HTML and can break the embedded
  document. Application mitigation should remove the prototype or pass the
  Webview a served URL; the transparent encoding fix belongs in Rio's outer
  HTML serializer.
- The security consequence is currently a latent top-document injection
  primitive, not demonstrated stored XSS. The only current source is trusted
  repository content, and untrusted Webview HTML would already be unsafe for
  separate reasons.
- The crawler path should be described in terms of Rio's observed design: Rio
  deliberately prebuilds state for detected crawler User-Agents. The finding
  does not depend on a blanket claim that every modern crawler is incapable of
  JavaScript or WebSockets.

## Terminology and Request Paths

### Ordinary Rio browser path

Rio normally serves a lightweight HTML shell. Its frontend opens a WebSocket,
receives messages describing the component tree, and constructs the page in
the browser. On this path the initial HTML contains:

```javascript
globalThis.initialMessages = [];
```

The Webview HTML arrives later as JSON over the WebSocket. A `</script>` byte
sequence in a WebSocket message has no top-level HTML parsing significance.

### Rio crawler path

Rio detects selected crawler User-Agents in the installed
`rio/app_server/fastapi_server.py` at lines 511-519. For those requests it
builds a session immediately, records the messages that would normally travel
over the WebSocket, and includes them in the initial response. This avoids
requiring the crawler to establish the normal WebSocket session.

This is described here as "crawler SSR" because that is how the current smoke
test and finding refer to it. It is not conventional semantic-HTML SSR: the
server embeds prebuilt component state, and Rio's frontend still has to replay
that state to construct the page.

## Exact Application Trigger

1. `app/app/pages/home.py:273-284` defines `ExampleJSPage`.
2. `app/app/pages/home.py:277-281` constructs:

   ```python
   rio.Webview(
       content=load_from_html("JSPages/test.html"),
   )
   ```

3. `app/app/pages/home.py:303` includes `ExampleJSPage()` unconditionally on
   the public `/` page.
4. `app/JSPages/test.html:12` contains:

   ```html
   <script src="test.js"></script>
   ```

5. `app/app/scripts/utils.py:196-210` reads `test.js` and replaces that tag
   with a literal inline script:

   ```html
   <script>
   document.getElementById(...);
   </script>
   ```

6. Rio's `Webview` serializer stores the full HTML document as the component's
   `content` string. The installed implementation is in
   `venv/lib/python3.12/site-packages/rio/components/webview.py:61-69`.

The prototype dates back to commit `6dfa41d` (`JSPages`) and currently displays
"Hello from JSPages", a test button, and an alert. It is demonstration content,
not part of the product's core home-page behavior.

## Framework Serialization Defect

For a crawler request, the installed Rio server performs this replacement in
`venv/lib/python3.12/site-packages/rio/app_server/fastapi_server.py:592-595`:

```python
html_ = html_.replace(
    '"{initial_messages}"',
    json.dumps(initial_messages),
)
```

The placeholder appears inside a classic inline script in
`venv/lib/python3.12/site-packages/rio/frontend files/index.html:37-48`:

```html
<script>
    ...
    globalThis.initialMessages = "{initial_messages}";
</script>
```

After placeholder replacement, the response is conceptually:

```html
<script>
globalThis.initialMessages = [{
    "content": "<html> ... <script>prototype code</script>
                                                   ^
                         HTML closes the outer script here
    ...",
    "root_component_id": 123
}];
</script>
```

`json.dumps()` makes the value valid JSON, but valid JSON is not automatically
safe to embed in HTML. It does not escape the `<` in `</script>`. Escaping the
forward slash as `<\/script>` would also prevent this particular terminator,
but escaping `<` as `\u003c` at the final HTML-embedding boundary is the more
general and conventional protection.

The essential browser rule is:

> While parsing a classic script element, the HTML tokenizer does not honor
> JavaScript or JSON string boundaries. A literal `</script>` closes the
> element before the JavaScript parser receives the source.

## Reproduction Evidence

Two independent reproductions confirmed the same boundary failure.

### Live development-server reproduction

A Googlebot-style request to `/` returned HTTP 200 and contained four literal
`</script>` sequences and no `<\/script>` representation. The first closing
tag originating from the serialized Webview content occurred immediately
after the inlined `test.js` button/alert code. The remaining component JSON,
including `root_component_id`, appeared after that closing tag in the raw
top-level document.

The development server was allowed to exit through its timeout; no process was
left running.

### Isolated TestClient reproduction

An isolated `FastAPI TestClient` reproduction used the same Googlebot
User-Agent as `app/tests/test_smoke_pages.py` and a temporary SQLite database.
On the clean checkout it produced the following snapshot (the exact offsets
can change as the component tree changes):

- HTTP status: `200`
- response length: `97,304` bytes
- `globalThis.initialMessages` starts at offset `4,493`
- the Webview's premature `</script>` occurs at offset `35,042`
- `"root_component_id"` occurs at offset `96,904`
- Rio's intended outer `</script>` occurs at offset `96,939`
- the script element produced by Python's `HTMLParser` does not contain
  `root_component_id`

The important ordering is:

```text
initialMessages start
    < Webview's closing script tag
    < root_component_id
    < Rio's intended closing script tag
```

The Webview terminator therefore cuts off roughly 62 KB before the root marker.
The parsed JavaScript ends inside a quoted value, so the assignment is invalid;
this is not merely a case of one optional field being omitted.

### Confirmed route scope

The isolated reproduction found:

- crawler `/`: broken
- crawler `/about`: unaffected
- crawler `/faq`: unaffected
- crawler `/pricing`: unaffected
- crawler `/contact`: unaffected
- crawler `/login`: unaffected
- normal-browser `/`: unaffected and receives `initialMessages = []`

The current application trigger is therefore limited to the home page, where
the only `load_from_html()` Webview is mounted. The framework defect is broader:
any crawler-visible serialized component string containing a literal
`</script>` can terminate the bootstrap script.

## Present Impact

### Active rendering/SEO defect

The crawler response returns HTTP 200, but its bootstrap JavaScript is
syntactically incomplete. Rio cannot reconstruct the component tree from
`initialMessages`. The crawler-oriented rendering path therefore silently
fails on the public home page.

This can be missed during ordinary manual testing because the normal WebSocket
path is unaffected.

### Latent top-document injection primitive

If attacker-controlled serialized text contained a sequence such as:

```html
</script><script>attackerCode()</script>
```

the first tag would terminate Rio's bootstrap script and the second could be
parsed as a new script in the top-level document. Other active HTML constructs
could likewise be interpreted after the premature termination.

No such input path exists in the current implementation:

- the Webview reads a fixed repository-controlled file;
- `test.js` is also repository-controlled;
- no user, CMS, database, or remote-fetch content reaches this call;
- the existing prototype script does not execute in the parent document; it
  instead causes the parent bootstrap assignment to become invalid.

The correct current description is therefore "latent injection primitive,"
not "active stored XSS." Exploit impact would depend on who receives or
executes crawler-mode responses and whether deployment caching broadens their
audience. The affected mode is not restricted to a genuine search engine,
because any HTTP client can send a crawler-like User-Agent.

### Separate Webview trust warning

Fixing crawler serialization would not make `rio.Webview` safe for untrusted
HTML. Rio 0.12.2 renders full HTML documents through an unsandboxed,
same-origin `iframe.srcdoc`, while HTML fragments are inserted and their script
elements deliberately executed by the frontend. Treat Webview content as
trusted code unless a separate, deliberately sandboxed design is introduced.

## Why the Existing Test Misses It

`app/tests/test_smoke_pages.py:59-63` already requests every public page with a
Googlebot User-Agent, but it asserts only:

```python
assert resp.status_code == 200
assert "initialMessages" in resp.text
```

Both conditions remain true. Rio successfully builds the server-side session
and returns HTML; the failure occurs when an HTML parser interprets the inline
script. The test proves server generation, not a valid or replayable bootstrap
payload.

There is a second false-negative path when pytest runs from the repository
root. `load_from_html("JSPages/test.html")` currently resolves that path against
the process working directory. From the repository root the file is not found,
Rio catches the component build exception, and the same weak status/text
assertions still pass without serializing the Webview content that triggers the
bug. The supported outer `app/` working directory does load the prototype and
reproduces the premature script close. A regression must therefore prove the
prototype fixture loaded before it evaluates the serialization boundary.

## Ownership and Remediation Options

### 1. Remove the prototype from the public home page

Recommended immediate application mitigation.

Remove `ExampleJSPage()` from `HomePage`, and remove the now-unused class/import
if the prototype is not otherwise needed. This eliminates the current trigger
and removes demonstration content from the production-facing home page.

This does **not** fix Rio's general serializer defect. A different component
string containing `</script>` could reintroduce it later.

### 2. Serve retained prototype content by URL

If the prototype is intentionally retained, serve its HTML/CSS/JS as an actual
same-origin resource and give `rio.Webview` a `rio.URL` pointing to that
resource. The crawler bootstrap then serializes a URL rather than the
script-bearing HTML document.

Simply leaving `test.js` external inside an HTML string is insufficient:
`<script src="test.js"></script>` still contains the dangerous closing tag.

This is another application-level mitigation, not a framework fix.

### 3. Make Rio's JSON embedding HTML-safe

This is the complete framework-level fix. Rio should encode the final JSON
representation for safe placement inside a script element, for example:

```python
initial_messages_json = json.dumps(initial_messages)
initial_messages_json = initial_messages_json.replace("<", "\\u003c")
```

Some implementations additionally escape `>`, `&`, and JavaScript line
separator characters. The important property is that the response source no
longer contains a literal `<` that can begin an HTML closing tag, while the
JavaScript parser reconstructs the original `<` character in the runtime
string passed to the Webview.

This encoding belongs around the final `json.dumps(initial_messages)` result in
Rio, not inside the component data itself.

As checked on 2026-07-11:

- this repository pins `rio-ui==0.12.2` in `requirements.txt`;
- 0.12.2 is the latest PyPI release;
- Rio upstream `main` at commit
  `90258d81e34d2e3bb0b74e0ab5c03f06f4e92919` still uses plain
  `json.dumps(initial_messages)` at this boundary.

There is therefore no released upgrade that fixes the issue at the time of
this investigation. Recheck upstream before carrying a fork or local patch.

### 4. Carry a temporary Rio fork or patch

If crawler rendering must be hardened before an upstream release, use a pinned
Rio fork/package containing the serializer fix. Do not edit files directly in
`venv/`; those changes are untracked, machine-local, and disappear when the
environment is recreated.

## Approaches to Avoid

### Do not blindly rewrite the Webview's real closing tags

Changing `</script>` to `<\/script>` or `&lt;/script>` in the value returned by
`load_from_html()` is not a clean general solution. That mutated value is later
given to the iframe as actual HTML, where the script needs a real closing tag.
The result can leave the embedded script unterminated or change its content.

The safe representation must exist only while the value is embedded in the
outer top-level HTML source and must decode back to the original value before
the Webview consumes it.

### Do not rely on `html.escape()` for script data

HTML script elements use raw-text parsing rules. General HTML text/attribute
escaping is not a substitute for a serializer designed for JSON embedded in a
script element.

### Do not treat removal of the prototype as the general security fix

Removing it repairs the current home page but leaves the Rio boundary capable
of failing on any future component state containing `</script>`.

## Recommended Resolution Order

1. Add a regression test that fails on the current response.
2. Remove the demonstration Webview from the public home page unless there is
   a concrete requirement to keep it.
3. Verify crawler `/` and the ordinary browser path.
4. Prepare a minimal upstream Rio reproduction and report the unsafe
   serialization boundary to the maintainers, using their security-reporting
   route if available because of the injection angle.
5. If crawler rendering is production-critical, decide whether to carry a
   pinned fork until an upstream release is available.

## Regression Test Plan

### Repository-level response test

Strengthen `test_public_page_renders` or add a focused home-page regression:

1. Ensure `JSPages/test.html` resolves as it does in production. Either make
   `load_from_html()` path-independent first, or have the test enter the outer
   `app/` directory with a context that always restores the original working
   directory.
2. Request `/` using `CRAWLER_UA` and the existing temporary database fixture.
3. Assert that a unique prototype sentinel such as `Hello from JSPages` is in
   the serialized response, so a swallowed component-build failure cannot make
   the test pass.
4. Parse the response as HTML rather than searching only the raw string.
5. Find the script element containing `globalThis.initialMessages`.
6. Assert that the same parsed script contains `root_component_id`.
7. Extract and validate the complete `initialMessages` assignment where
   practical.

The minimal invariant is:

```text
initialMessages start < root_component_id < intended script close
```

All three markers must belong to the same parsed script element.

### Framework-level adversarial test

An upstream Rio regression should create crawler-visible component state with
a sentinel such as `</script><script id="injection-sentinel">` and verify that:

- the generated response contains an HTML-safe JSON representation;
- parsing the document produces no extra sentinel script element;
- `initialMessages` remains complete and replayable;
- the decoded component value still contains the original text.

### Browser smoke test

For higher confidence, load `/` in a browser configured with the Googlebot
User-Agent and assert that Rio creates its root component and renders expected
home-page content. This catches failures beyond raw response structure.

After an application change, run the repository-required checks. The crawler
regression itself must establish and verify the outer `app/` asset context as
described above, even when pytest is launched from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 \
  venv/bin/python -m pytest app/tests/test_smoke_pages.py -x -p no:cacheprovider
cd app && timeout 5 ../venv/bin/rio run --port 8XXX
```

Use `GET`, not `HEAD`, for the page probe.

## Acceptance Criteria

- A crawler `GET /` returns HTTP 200 with one complete, parseable
  `initialMessages` bootstrap assignment.
- `root_component_id` is inside the parsed bootstrap script, not spilled into
  top-level document text.
- The home page renders under a crawler User-Agent.
- The ordinary browser/WebSocket path still renders the home page.
- The crawler smoke test fails if a component value prematurely terminates the
  bootstrap script.
- If the prototype remains, its button behavior still works within the
  Webview.
- No solution implies that arbitrary untrusted Webview HTML is safe.

## Manual Recheck Recipe

In one terminal, start a short-lived development server from the outer `app/`
directory on an unused port:

```bash
cd app
timeout 15 ../venv/bin/rio run --port 8123
```

While it is running, fetch the home page from another terminal with the same
crawler User-Agent used by the tests and save only the temporary response
outside the repository:

```bash
curl -sS \
  -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' \
  http://127.0.0.1:8123/ \
  > /tmp/rioboilerplate-crawler-home.html
```

Then check the marker ordering:

```python
from pathlib import Path

html = Path("/tmp/rioboilerplate-crawler-home.html").read_text()
start = html.index("globalThis.initialMessages")
first_close = html.index("</script>", start)
root = html.index('"root_component_id"', start)

print({
    "initial_messages": start,
    "first_close": first_close,
    "root_component_id": root,
    "premature": first_close < root,
})
```

This offset check demonstrates the raw ordering. The automated regression
should additionally use an HTML parser so it validates the browser-relevant
script boundary.

## Open Questions for Follow-up

- Is `ExampleJSPage` intentionally part of the template, or can the entire
  prototype be removed?
- Does Rio have a private security-reporting path for the injection aspect, or
  should this be filed as a normal crawler-rendering issue?
- Is crawler rendering important enough for this template to carry a temporary
  Rio fork?
- Does the target deployment use a shared cache or CDN that varies responses by
  User-Agent? Rio's crawler-specific output should be reviewed together with
  cache headers before drawing conclusions about audience broadening.

## Upstream References

- Rio package: <https://pypi.org/project/rio-ui/>
- Rio crawler serialization at the checked upstream commit:
  <https://github.com/rio-labs/rio/blob/90258d81e34d2e3bb0b74e0ab5c03f06f4e92919/rio/app_server/fastapi_server.py#L509-L595>
- Rio inline bootstrap template at the checked upstream commit:
  <https://github.com/rio-labs/rio/blob/90258d81e34d2e3bb0b74e0ab5c03f06f4e92919/frontend/index.html#L38-L49>
