# WebGuard Phase 3 — Security boundaries and residual risks

## Enforced by this package

1. **Authorization before access.** A request requires a `TargetAuthorization` whose validity window is active. The hostname must match an exact allowlist entry or a deliberate `*.domain` entry (subdomains only); the port and decoded canonical path must also be allowed.
2. **URL parsing.** Only `http` and `https` are accepted. Credentials in URLs, malformed ports, control characters, backslashes, path traversal, malformed percent escapes, encoded slash/backslash, and double-encoded traversal patterns are rejected.
3. **Address policy.** Normal mode blocks loopback, RFC1918/ULA private ranges, link-local, reserved, multicast, unspecified and broadcast destinations. Known cloud metadata names/IPs are always denied. A lab destination needs both deployment setting `isolated_lab_enabled=True` and grant field `isolated_lab=True`.
4. **DNS pinning at connector boundary.** `ScopeBoundResolver` validates every answer returned by `getaddrinfo`; if any answer is disallowed (including a mixed public/private set), the resolution fails closed. It returns numeric addresses to aiohttp with DNS cache disabled; TLS still uses the original URL hostname for SNI and certificate checks.
5. **Redirect validation.** Redirects are not automatically followed. Every `Location` is resolved relative to the current URL, validated against the same grant, and then independently resolved by the safe resolver. Credentials (`Authorization`, `Cookie`) are stripped when the origin changes.
6. **Resource controls.** Per-job request count, concurrent in-flight jobs/requests, per-request timeout, total job duration, response bytes and redirect count are capped. Cancellation, denials, timeouts and oversized responses can be sent to the audit sink.

## Integration obligations

- Authenticate the actor and prove the authorization record belongs to them or to an authorized operator before constructing a client.
- Load the grant from persistent storage; do not accept an arbitrary grant supplied by the web client.
- Route all scanner HTTP fetches through `ScopeBoundHttpClient` or an equivalent approved adapter. A raw `requests`, `httpx`, `urllib`, subprocess `curl`, or unguarded browser network stack bypasses this protection.
- The package does **not** make arbitrary Playwright navigation safe by itself. Browser subresources, service workers, WebSockets, downloads, popups and browser-specific resolution require Playwright request interception plus a network-level egress boundary. The strongest design places the browser/container in an isolated network with outbound firewall rules or routes all traffic through an independently enforced scope-aware gateway. Do not rely on a one-time `page.goto()` URL check.
- Enforce egress policy at container/network level too. Application checks cannot protect against compromised processes with another route to the network.
- Audit authorization creation, edits and revocation transactionally in the production database. Pass `authorization_check` to the client (for example, `lambda: registry.is_current(grant)`) so later hops and DNS resolution fail if the grant changes. The scheduler must also cancel any already-running job immediately on revocation. The included in-memory registry is only a contract/test implementation.
- Review authorization evidence and expiration before each job, and cancel active jobs immediately when a grant is revoked or scope changes.
- Never store credentials, API keys or secrets in the repository. Use a secrets manager or environment injection.

## Residual risks and assumptions

- The resolver validates IPs returned by the OS resolver and gives those numeric addresses to aiohttp, reducing the DNS check/use gap for connections made by this client. The operating system, network routing, transparent proxies, NAT, and infrastructure still need hardening. This package cannot verify external routing behavior.
- The URL/path policy is deliberately conservative but cannot infer application-specific authorization semantics. For example, an allowed path with a sensitive query parameter may still be dangerous; scope owners must define suitable path and query rules for their target.
- Generic HTTP response handling does not model every protocol feature. WebSockets, CONNECT, proxying, browser subresources and protocol upgrades are not implemented.
- The `AuthorizationRegistry` does not persist grants and is not multi-process safe. It is not a production database substitute.
- `AuditSink` must write safely and reliably. A production audit sink should avoid logging secrets or complete sensitive response bodies.
- This package cannot establish legal authorization itself. The caller must retain evidence and ensure the target owner explicitly authorized the planned actions.

## Fail-closed behavior

If scope validation, hostname normalization, DNS resolution or IP classification fails, the attempted request/navigation must be denied. Do not add catch-all fallbacks that continue without validation.
