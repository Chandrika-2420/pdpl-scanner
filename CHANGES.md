# PDPL scanner v1.2: change notes

## v1.2.3: table tidy-up (no change to findings or scores)

- Other www.google.com requests, such as Google helper scripts and pings, are now shown as "Google (other services)". They no longer appear as an unidentified domain.
- A domain that is not in the vendor list is never labelled "Tracking" in the vendor table. It shows "Calls seen (unidentified)", and the advisory lists its full address, including domains seen only after Reject.


## v1.2.2: fixes from the third Careem scan

| Item | What was wrong | Fix |
|---|---|---|
| CRITICAL "Tracking continues after Reject" (Meta) | Meta's pixel setup file (`connect.facebook.net/signals/config/...`) is a code download. Its extra parameters made v1.2.1 count it as a tracking call. | Known setup and loader files (Meta config, gtag/destination, tag/sdk loaders) count as code downloads again. Real beacons such as `facebook.com/tr?ev=PageView` still count as tracking. |
| Evidence on consent findings | The report named the vendor but not the call that was seen. | Every tracking-call finding now shows an example request, for example `www.facebook.com/tr?ev=PageView&id=...`. Each finding can be checked and defended with the client. |
| Quoted evidence for sharing, purposes and retention | Passes could quote an off-topic line. | The quote now comes from a line that is about the topic. |


## v1.2.1: fixes from the second Careem scan

| Item | What was wrong | Fix |
|---|---|---|
| PASS "UAE PDPL referenced" | The notice never mentions the PDPL, the Decree-Law or the Data Office. The check accepted "United Arab Emirates) is the data controller for the Personal Data". | A UAE location near "personal data" no longer counts. The notice must name the law, the Decree-Law number or the Data Office. Careem now gets "UAE PDPL not referenced". |
| LOW "No Arabic version" | Careem's Arabic notice is at `/ar-AE/privacy-notice-technologies/`. The language switch on the site is a button, not a link. | The scanner now tries the Arabic twin of the notice address (`/en-AE/` to `/ar-AE/`, `/en/` to `/ar/`, `?lang=en` to `?lang=ar`) and recognises language-switch buttons. |
| CRITICAL "Tracking continues after Reject" (cookie only) | `_fbp` was reported as "written after Reject" although Meta received no requests after Reject. | The cookie comparison is now taken just before the reload, which removes a timing race. A rewritten cookie with no tracking calls after Reject is now HIGH ("Tracking cookie rewritten after Reject"). The evidence says what changed and whether the vendor's script was still downloaded. CRITICAL needs real tracking calls. |
| "google.com, unclassified" in the vendor table | Google tag calls sent to www.google.com on paths the scanner did not know. | These calls are now classified as Google Ads, Google Analytics or Google Maps. |
| Weak evidence lines | For example, "Recipients and sharing" quoted an indemnity clause that only mentions "third parties". | The evidence now comes from the paragraph with the most matching wording. |

Still reported for Careem, and confirmed correct against the live notices:
- "Breach handling not found": neither notice describes breach notification.
- "Data portability not found".
- "Legitimate interests".
- The complaint route names only a generic authority.


## False positives fixed (found while checking the Careem report)

| Careem finding | What was wrong | Fix |
|---|---|---|
| CRITICAL "No privacy notice found" | The footer links to `/en-AE/privacy-policy/`, which is a hub page ("Select jurisdiction") that links on to the real notices. The scanner rejected any page under 150 words and never followed those links. | Hub pages are now followed and up to 3 linked notices are read together. Probes also try the site's language folder (`/en-AE/privacy...`). Pages blocked by bot protection are reported as "could not be read" (not scored, grade capped at B), not as "no notice". |
| HIGH "No published way to exercise privacy rights" | Knock-on effect of the missed notice. The check also accepted only email addresses. | The finding is no longer added when no notice exists, because the missing notice already covers it. A request form, portal or contact link on the same site now counts as a route. |
| HIGH "Transfers abroad not disclosed" | Knock-on effect of the missed notice. Careem's notice does cover transfers (Section 8). | Fixed by the notice discovery change. |
| CRITICAL "Trackers load before consent" (Google Analytics / Ads) | Requests fired in the 1.5 s after the Accept click were still labelled "before consent". | The phase now switches to Accept before the click. |
| CRITICAL "Tracking continues after Reject" | Any download of `fbevents.js` counted as tracking. The `_fbp` cookie set before the click was still in the browser after Reject and was counted as new tracking. | Each vendor is now classed as Tracking, Pings (consent denied) or Script only. Cookies are compared before and after the Reject click. A leftover cookie is reported as a low finding, not as tracking. |
| LOW "Server software versions disclosed: AmazonS3" | Any digit in the header was treated as a version number. | Only real version patterns count (nginx/1.18, PHP 8.1). |
| "Google AdSense" in the vendor table | `googlesyndication.com` is also used by Google Ads tags. | Relabelled Google Ads. |
| LOW "Unidentified third parties" (csper.io, vimeo.com) | Not in the vendor list. | Added these plus 61 more vendor domains. Unknown domains now cost points only when they make calls before consent. |
| Advisory "This website has a UAE version" | The page was already the UAE version (`lang="en-AE"`). | Skipped when the page is already the UAE version. |

Also changed:
- A form with no notice of its own, on a page that only has a footer privacy link, is now medium instead of high.
- The vendor table shows Tracking, Pings (consent denied), Script only or Loaded instead of a dot.

Still reported, and real for Careem:
- The restaurant sign-up form has no privacy text.
- The notice relies on "legitimate interests".
- The notice does not mention the UAE Data Office or the PDPL.
- The CSP allows `unsafe-inline`.

## Speed

On local test sites with 200 ms of simulated latency, the same site took:

| Version | Time |
|---|---|
| v1.1 | 81 s |
| v1.2, one session at a time (512 MB servers) | about 30 s |
| v1.2, sessions side by side (1.5 GB+ servers) | about 18 s |

What changed:
- Fixed waits are replaced by smart waits. Busy sites never reach "networkidle", so the old wait always ran its full 8 s plus 4 s on every page.
- Guessing privacy addresses stops as soon as a notice is found.
- The TLS, HTTP and security.txt checks run while the browser works.
- Images are blocked on the notice and form pages.
- The homepage tab is closed before the text pages open, which saves memory.
- The Docker image installs only the headless browser, so it is smaller and starts faster.

Render settings:
- **Free** (0.1 CPU, 512 MB) starves Chromium and spins down after 15 minutes idle, so the first scan also waits about a minute for the server to start. This is likely a big part of the 2 to 5 minutes you saw.
- **Starter** (0.5 CPU) will be noticeably faster.
- **Standard** (1 CPU, 2 GB) also turns on side-by-side sessions automatically.
- `SCAN_PARALLEL=1` or `SCAN_PARALLEL=0` overrides the automatic choice.

## Deploy

Replace the four files (`pdpl_scanner.py`, `app.py`, `Dockerfile`, `requirements.txt`) in the repo and push. No new environment variables are required. Each finished job page now shows how long the scan took. The Render log line "scan done ... in N s" gives a per-stage breakdown.
