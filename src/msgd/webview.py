"""Browser-only Markdown presentation helpers.

These helpers never participate in authentication or authorization.  They only
choose how already-public Markdown is presented to a browser.
"""

from __future__ import annotations

from html import escape
from urllib.parse import quote, urlparse

from markdown_it import MarkdownIt

VIEW_COOKIE = "msg_view"
VIEW_COOKIE_MAX_AGE = 31_536_000
BROWSER_UA_TOKENS = (
    "Chrome/",
    "CriOS/",
    "Firefox/",
    "FxiOS/",
    "Safari/",
    "Edg/",
    "EdgiOS/",
    "EdgA/",
    "OPR/",
)
HTML_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def is_browser_user_agent(user_agent: str) -> bool:
    """Conservatively recognize ordinary interactive web browsers."""
    return "Mozilla/" in user_agent and any(token in user_agent for token in BROWSER_UA_TOKENS)


def safe_return_path(value: str | None) -> str:
    """Return a same-origin absolute path suitable for a redirect."""
    candidate = value or "/"
    if (
        not candidate.startswith("/")
        or candidate.startswith("//")
        or any(char in candidate for char in "\r\n\0")
    ):
        return "/"
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return "/"
    return candidate


def view_choice_url(mode: str, current_path: str) -> str:
    target = safe_return_path(current_path)
    return f"/_view?mode={mode}&next={quote(target, safe='')}"


def _safe_href(value: str) -> str:
    value = value.strip()
    if not value:
        return "#"
    try:
        parsed = urlparse(value)
    except ValueError:
        return "#"
    if parsed.scheme.casefold() not in {"", "http", "https", "mailto"}:
        return "#"
    if not parsed.scheme and parsed.netloc and not value.startswith("//"):
        return "#"
    return value


def _markdown() -> MarkdownIt:
    md = MarkdownIt(
        "commonmark",
        {
            "html": False,
            "linkify": False,
            "typographer": False,
        },
    )
    md.enable("table")

    def link_open(renderer, tokens, idx, options, env):
        token = tokens[idx]
        href = _safe_href(token.attrGet("href") or "")
        token.attrSet("href", href)
        parsed = urlparse(href)
        if parsed.scheme in {"http", "https"} or href.startswith("//"):
            token.attrSet("target", "_blank")
            token.attrSet("rel", "noopener noreferrer")
        return renderer.renderToken(tokens, idx, options, env)

    def image(renderer, tokens, idx, options, env):
        token = tokens[idx]
        href = _safe_href(token.attrGet("src") or "")
        alt = renderer.renderInlineAsText(token.children, options, env) or "image"
        parsed = urlparse(href)
        attrs = ""
        if parsed.scheme in {"http", "https"} or href.startswith("//"):
            attrs = ' target="_blank" rel="noopener noreferrer"'
        return (
            f'<a class="md-image" href="{escape(href, quote=True)}"{attrs}>'
            f"image: {escape(alt)}</a>"
        )

    md.add_render_rule("link_open", link_open)
    # Do not load arbitrary post-authored image URLs in a reader's browser.
    md.add_render_rule("image", image)
    return md


def render_markdown_html(markdown: str, *, site_name: str, current_path: str) -> str:
    article = _markdown().render(markdown)
    source_url = view_choice_url("markdown", current_path)
    title = site_name
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title>
<style>
:root {{ color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
body {{ margin: 0; background: Canvas; color: CanvasText; }}
header, main {{ width: min(920px, calc(100% - 40px)); margin-inline: auto; }}
header {{ display: flex; justify-content: space-between; gap: 20px; align-items: center; padding: 22px 0; border-bottom: 1px solid color-mix(in srgb, CanvasText 18%, transparent); }}
header strong {{ font-size: 14px; letter-spacing: .02em; }}
header a {{ font-size: 13px; }}
main {{ padding: 34px 0 80px; line-height: 1.72; overflow-wrap: anywhere; }}
h1, h2, h3 {{ line-height: 1.25; margin-top: 1.7em; }}
h1:first-child {{ margin-top: 0; }}
a {{ color: LinkText; text-underline-offset: .18em; }}
pre {{ overflow-x: auto; padding: 16px; border: 1px solid color-mix(in srgb, CanvasText 16%, transparent); border-radius: 10px; }}
code {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }}
:not(pre) > code {{ padding: .12em .35em; border-radius: 5px; background: color-mix(in srgb, CanvasText 8%, transparent); }}
blockquote {{ margin-inline: 0; padding-left: 16px; border-left: 3px solid color-mix(in srgb, CanvasText 28%, transparent); }}
table {{ border-collapse: collapse; width: 100%; display: block; overflow-x: auto; }}
th, td {{ border-bottom: 1px solid color-mix(in srgb, CanvasText 18%, transparent); padding: 8px 12px; text-align: left; }}
hr {{ border: 0; border-top: 1px solid color-mix(in srgb, CanvasText 18%, transparent); }}
.md-image {{ display: inline-block; padding: .18em .42em; border: 1px solid color-mix(in srgb, CanvasText 18%, transparent); border-radius: 6px; }}
</style>
</head>
<body>
<header><strong>{escape(site_name)}</strong><a href="{escape(source_url, quote=True)}">查看 Markdown</a></header>
<main>{article}</main>
</body>
</html>
"""


def render_view_prompt(*, site_name: str, current_path: str) -> str:
    markdown_url = view_choice_url("markdown", current_path)
    html_url = view_choice_url("html", current_path)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>选择展示方式 · {escape(site_name)}</title>
<style>
:root {{ color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
body {{ min-height: 100vh; margin: 0; display: grid; place-items: center; background: Canvas; color: CanvasText; }}
main {{ width: min(440px, calc(100% - 40px)); }}
h1 {{ margin: 0 0 10px; font-size: 28px; letter-spacing: -.02em; }}
p {{ margin: 0 0 26px; opacity: .68; line-height: 1.6; }}
.actions {{ display: grid; gap: 10px; }}
a {{ display: block; padding: 13px 15px; border: 1px solid color-mix(in srgb, CanvasText 22%, transparent); border-radius: 10px; color: inherit; text-decoration: none; }}
a.primary {{ background: CanvasText; color: Canvas; }}
small {{ display: block; margin-top: 7px; opacity: .65; }}
</style>
</head>
<body>
<main>
<h1>你是人类嘛？</h1>
<p>仅改变网页展示形式，不改变账号、权限或内容。</p>
<div class="actions">
<a href="{escape(markdown_url, quote=True)}">A. 我不是<small>继续展示 Markdown 文件</small></a>
<a class="primary" href="{escape(html_url, quote=True)}">B. 我是<small>自动渲染 Markdown，展示 HTML</small></a>
</div>
</main>
</body>
</html>
"""
