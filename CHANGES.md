# UAE PDPL scanner v1.3 (final): changes from the original v1.1

Replace these five files in the repo and push: `pdpl_scanner.py`, `app.py`, `Dockerfile`, `requirements.txt` and this file. `requirements.txt` has new packages (`pypdf`, `cryptography`), so let Render rebuild the image. No environment variables are required.

## False positives fixed

- **"No privacy notice found":** hub pages that list several notices are now followed, and the notices are read together. The scanner also tries the site's language folder (`/en-AE/privacy`) and reads notices published as PDF files. A notice the site refuses to serve is reported as "could not be read" and is not scored; it is no longer reported as missing.
- **Knock-on findings when no notice is found:** "No way to exercise rights" is no longer added separately, so one cause is no longer counted three times.
- **Trackers "before consent" that fired on the Accept click:** requests caused by the Accept or Reject click now belong to that choice.
- **Script downloads counted as tracking:** each vendor is now shown as Tracking, Pings (consent denied) or Script only. Meta's pixel setup file and Google tag loaders count as code downloads.
- **"Tracking continues after Reject" based on a leftover cookie:** cookies from before the choice are reported as left in place. A cookie rewritten with no tracking calls is a high finding. Critical now needs real tracking calls after Reject.
- **A "Cookie Policy" link, a footer cookie note, an Adobe `cmp-` block or a newsletter pop-up taken for a consent banner:** a banner must now float over the page, be a known consent tool, or sit in view with consent buttons.
- **"AmazonS3" read as a server version:** only real version numbers count.
- **Notice wording the checks did not recognise:**
  - correction rights written as "data to be amended or rectified";
  - transfers written as "transferred outside India";
  - a contact route given as a request form or help centre.
- **A CSP set in a meta tag reported as missing**, and a report-only CSP reported as missing.
- **"Notice written for India's DPDP / the GDPR"** on a site with no UAE link is now an advisory. The cover shows a red scope warning asking you to confirm the PDPL applies. "EU GDPR" and "UK GDPR" are named separately.
- **Vendor labels:** googlesyndication is now shown as Google Ads, not AdSense. 65 more vendor domains are recognised, and other Google calls show as "Google (other services)" instead of an unknown domain.

## False negatives fixed (things the scanner used to miss)

- **Tags that load only after the visitor scrolls or moves the mouse.** This affected Emaar, where about 20 trackers loaded after one scroll. Each session now scrolls and moves the mouse like a visitor; scrolling is not consent. A banner that closes itself on scroll is flagged.
- **"UAE PDPL referenced" passing because a UAE address appeared near "personal data":** the notice must now name the law, the Decree-Law or the Data Office.
- **An Arabic version reached only through a language button:** the Arabic copy of the notice (`/ar-AE/...`) is now checked.
- **Google Analytics sent through the site's own domain** (server-side tagging) is now recognised.
- **Footers, links and forms that load only when scrolled to** are now read.
- **A bot-protection page** now stops the scan with a clear message. Before, it produced a clean-looking report.
- **A settings button on the cookie policy page** now counts as a way to withdraw consent, and the report says where it was found.

## Evidence quality

- Each tracking finding shows an example of the actual call, for example `www.facebook.com/tr?ev=PageView`.
- Quoted evidence comes from the sentence about the topic, such as the actual date line or the sharing paragraph.
- The vendor table shows "not tested" when there was no banner to click.

## Speed and stability

- Smart waits replace fixed sleeps, and notice discovery stops as soon as a notice is found.
- The network checks run alongside the browser, and images are blocked on text-only pages.
- On a server with 1.5 GB or more memory, the Accept and Reject sessions run side by side.
- On local test sites with simulated delay: 81 s with the original v1.1, about 40 s now on 512 MB plans, and about 25 s with 1.5 GB or more. Real sites take longer, especially on Render's free plan (0.1 CPU).
- Each browser session has a time limit (240 s, `SCAN_SESSION_LIMIT`), so one hung website cannot block the scan queue.
- The Docker image installs only the headless browser, which makes it smaller and faster to start.

## Optional settings

| Setting | Effect |
|---|---|
| `SCAN_PARALLEL` | `auto` (default), `1` or `0`: whether the Accept and Reject sessions run side by side. |
| `SCAN_SESSION_LIMIT` | Seconds before a browser session is stopped (default 240). |
| `SCAN_PROXY` | Scan through a UAE IP address (unchanged). |

## Still outside what an automated website scan can judge

- Banners shown only in some regions.
- Pages behind logins, and mobile apps.
- Back-end transfers abroad.
- Whether the notice wording is legally adequate.

The report lists these under "Not covered by this scan".
