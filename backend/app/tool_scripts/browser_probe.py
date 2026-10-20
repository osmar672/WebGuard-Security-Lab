"""Optional Playwright browser probe with conservative request routing."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--allow-lab', action='store_true')
    parser.add_argument('--public-only', action='store_true')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--accessibility', action='store_true')
    mode.add_argument('--browser', action='store_true')
    args = parser.parse_args()
    from playwright.sync_api import sync_playwright
    # Also deny resolved private and reserved destinations. External egress rules are still required
    # because a browser's internal networking behavior is more complex than a simple HTTP client.
    from app.scope import ScopeError, default_resolver, validate_target_url

    target_parts = urlsplit(args.target)
    allowed_origin = (target_parts.scheme, target_parts.hostname, target_parts.port or (443 if target_parts.scheme == 'https' else 80))
    findings: list[dict] = []
    summary: dict = {"visited_url": args.target, "console_errors": 0, "request_failures": 0,
                     "blocked_out_of_scope_requests": 0}
    console_errors: list[str] = []
    request_failures: list[str] = []
    blocked: list[str] = []
    final_url = args.target
    status = None
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-dev-shm-usage", "--no-sandbox"])
        context = browser.new_context(ignore_https_errors=False, service_workers="block")
        page = context.new_page()
        page.set_default_timeout(7000)

        def check_route(route):
            request = route.request
            url = request.url
            try:
                if request.resource_type in {"websocket", "eventsource"}:
                    raise ScopeError("long-lived connection not allowed in baseline probe")
                parts_original = urlsplit(url)
                validation_url = urlunsplit((parts_original.scheme, parts_original.netloc, parts_original.path or "/", "", ""))
                canonical, host, is_lab = validate_target_url(validation_url, allow_lab=bool(args.allow_lab), resolver=default_resolver)
                parts = urlsplit(canonical)
                origin = (parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
                if origin != allowed_origin:
                    raise ScopeError("cross-origin resource")
                route.continue_()
            except Exception:
                blocked.append(url[:500])
                route.abort("blockedbyclient")

        page.route("**/*", check_route)
        page.on("console", lambda message: console_errors.append(message.text[:400]) if message.type == "error" else None)
        page.on("requestfailed", lambda request: request_failures.append((request.url + " — " + (request.failure or "failed"))[:500]))
        try:
            response = page.goto(args.target, wait_until="domcontentloaded", timeout=15000)
            final_url = page.url
            status = response.status if response else None
            if response is not None and response.status >= 400:
                findings.append({"title": "Page returned an HTTP error status", "severity": "medium" if response.status >= 500 else "low",
                                 "url": final_url, "description": f"Browser navigation returned HTTP {response.status}.",
                                 "evidence": {"http_status": response.status}})
            if args.accessibility:
                result = page.evaluate("""() => {
                  const images = [...document.images].filter(x => !x.hasAttribute('alt'));
                  const buttons = [...document.querySelectorAll('button,[role=button]')].filter(x => !(x.innerText || x.getAttribute('aria-label') || x.getAttribute('title') || '').trim());
                  const inputs = [...document.querySelectorAll('input:not([type=hidden]),select,textarea')].filter(x => {
                    if (x.getAttribute('aria-label') || x.getAttribute('aria-labelledby')) return false;
                    if (x.labels && x.labels.length) return false;
                    return !x.closest('label');
                  });
                  const headings = [...document.querySelectorAll('h1,h2,h3,h4,h5,h6')].map(x => Number(x.tagName.slice(1)));
                  const missingLang = !document.documentElement.getAttribute('lang');
                  return { missing_image_alt: images.length, unnamed_buttons: buttons.length,
                    unlabeled_form_controls: inputs.length, missing_document_language: missingLang,
                    heading_levels: headings, title: document.title || '' };
                }""")
                summary["accessibility"] = result
                if result["missing_image_alt"]:
                    findings.append({"title": "Images missing alternative text", "severity": "medium", "url": final_url,
                                     "description": f"Found {result['missing_image_alt']} images without an alt attribute.",
                                     "evidence": {"count": result["missing_image_alt"]}})
                if result["unnamed_buttons"]:
                    findings.append({"title": "Buttons without an accessible name", "severity": "medium", "url": final_url,
                                     "description": f"Found {result['unnamed_buttons']} buttons without visible text, aria-label or title.",
                                     "evidence": {"count": result["unnamed_buttons"]}})
                if result["unlabeled_form_controls"]:
                    findings.append({"title": "Form controls without an accessible label", "severity": "medium", "url": final_url,
                                     "description": f"Found {result['unlabeled_form_controls']} form controls without a detectable label.",
                                     "evidence": {"count": result["unlabeled_form_controls"]}})
                if result["missing_document_language"]:
                    findings.append({"title": "Document language is missing", "severity": "low", "url": final_url,
                                     "description": "The document root does not declare a lang attribute.", "evidence": {}})
                levels = result.get("heading_levels", [])
                if any((later - prev) > 1 for prev, later in zip(levels, levels[1:])):
                    findings.append({"title": "Heading level skips detected", "severity": "low", "url": final_url,
                                     "description": "The document heading sequence skips a level; review the structure for assistive technology users.", "evidence": {}})
            else:
                try:
                    page.locator("body").wait_for(state="visible", timeout=3000)
                except Exception:
                    findings.append({"title": "Page body did not become visible", "severity": "medium", "url": final_url,
                                     "description": "A visible body element was not detected after navigation.", "evidence": {}})
        except Exception as exc:
            findings.append({"title": "Browser navigation failed", "severity": "medium", "url": args.target,
                             "description": f"Navigation failed ({type(exc).__name__}). Review the target availability and browser logs.", "evidence": {"error_type": type(exc).__name__}})
        finally:
            context.close()
            browser.close()
    summary.update({"final_url": final_url, "http_status": status, "console_errors": len(console_errors),
                    "console_error_samples": console_errors[:10], "request_failures": len(request_failures),
                    "request_failure_samples": request_failures[:10], "blocked_out_of_scope_requests": len(blocked),
                    "blocked_request_samples": blocked[:10]})
    if console_errors:
        findings.append({"title": "Browser console errors detected", "severity": "low", "url": final_url,
                         "description": f"Detected {len(console_errors)} browser console error(s). Samples are included after truncation.",
                         "evidence": {"samples": console_errors[:5]}})
    if blocked:
        findings.append({"title": "Out-of-scope browser requests were blocked", "severity": "info", "url": final_url,
                         "description": f"Blocked {len(blocked)} resource request(s) that did not match the explicitly authorized origin.",
                         "evidence": {"count": len(blocked)}})
    Path(args.output).write_text(json.dumps({"summary": summary, "findings": findings}, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
