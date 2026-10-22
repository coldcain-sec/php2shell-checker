[README.md](https://github.com/user-attachments/files/33822188/README.md)
# PHP2Shell Checker

A one-click way to check whether a website is running a PHP version affected by the October 2026 **PHP2Shell** vulnerabilities, **CVE-2026-109618** and **CVE-2026-109619** (both CVSS 9.2).

The flaws sit in the PHP runtime itself, not in any application, so a site can be exposed even when its own code is sound. On a vulnerable server an attacker can run commands without logging in. This tool reads the PHP version a site advertises and tells you plainly whether it needs the emergency update.

It is built for non-technical users, such as a board member, as much as for security teams. It runs entirely in the browser as a bookmarklet. There is no server, and nothing is sent to any third party.

> **Scope.** This reports advertised version information only. It is a fast first screen, not a full vulnerability scan. See [Limitations](#limitations).

---

## How to use it

1. Open [`index.html`](index.html) in a browser (or host it anywhere static).
2. Drag the **PHP2Shell check** button onto your browser's bookmarks bar.
3. Visit any website and click the bookmark. A panel appears with a clear verdict and the evidence behind it.

The bookmarklet checks the page you are on, plus that site's `/phpinfo.php` and `/info.php` if they exist. The readable source is in [`bookmarklet.js`](bookmarklet.js).

### Safe PHP versions

| Branch | Safe from | Status |
|---|---|---|
| 8.5 | `8.5.12` | Supported |
| 8.4 | `8.4.27` | Supported |
| 8.3 | `8.3.36` | Security fixes only |
| 8.2 | `8.2.35` | Security fixes only, end of life 31 Dec 2026 |
| 8.1 and older | No vendor fix in the version number | End of life, treat as at risk |

### What the verdicts mean

- **Action needed** a vulnerable or end-of-life PHP version was found.
- **Check with IT** an affected branch, patch level not shown.
- **Looks patched** the version includes the fix.
- **No version shown** the site hides its version.

---

## Why it is a bookmarklet, not a page with an address box

Browsers enforce the **same-origin policy**: one website cannot read another website's content or response headers. A plain page with an address box therefore cannot inspect an arbitrary site without a backend relay or a browser extension.

The bookmarklet sidesteps this by running on the site you are already viewing, which is the one place the browser allows the PHP version to be read directly. That is why you click it while on the site, rather than typing an address.

---

## Limitations

- **Advertised version only.** This is a first screen, not a vulnerability scan.
- **A hidden version is not proof of safety.** Many well-run sites suppress the version. That is good practice, not a verdict.
- **Backported fixes.** Linux distributions often patch the flaw while keeping an old-looking version number. Confirm an uncertain result with IT or the hosting provider, and check the package changelog for the CVE rather than the version string.
- **Content security policy.** A site with a strict CSP may block the result panel, which then falls back to a simple alert.

---

## Background

- [PHP emergency release and affected versions](https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html)
- CVE-2026-109618, CVE-2026-109619

---

## Licence

MIT. See [LICENSE](LICENSE).

## Author

Created by [Alan Cain](https://www.linkedin.com/in/alancain/).
