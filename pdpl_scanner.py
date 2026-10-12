#!/usr/bin/env python3
"""
UAE PDPL Website Scanner -> client-ready PDF report  (v1.4)
Law   : Federal Decree-Law No. 45 of 2021 on the Protection of Personal Data (UAE PDPL)
Run   : python pdpl_scanner.py           (asks for client details, then scans)
Setup : pip install playwright   then   python -m playwright install chromium
v1.1  : notice checks read only the main policy text (menus, contents lists and definitions ignored);
        flags notices written for other laws and unfinished placeholder text; more trackers recognised;
        grade capped when critical gaps exist; stricter CSP and cookie checks; dates in Gulf Standard Time.
v1.2  : fewer false positives: tags fired by the 'Accept' click are no longer counted as pre-consent; a vendor
        script that is only downloaded is reported separately from real tracking calls; cookies left over from
        before 'Reject' are not treated as tracking after 'Reject'; privacy-notice hub pages ("select your
        notice") are followed; request forms count as a privacy contact route; "AmazonS3"-style server names
        are no longer read as version numbers; no-notice results are not counted three times.
        Faster: smart waits instead of fixed sleeps, network checks run alongside the browser, images blocked
        on text-only pages, Accept and Reject sessions run side by side when the server has enough memory.
v1.3  : the page is scrolled like a visitor (many sites load tags only on the first scroll); banners that close on
        scroll are flagged; bot-protection pages stop the scan instead of producing a clean report; PDF privacy
        notices are read; a plain "Cookie Policy" link is no longer mistaken for a banner; first-party Google tags,
        meta-tag CSP, report-only CSP and footer forms in embedded frames are handled; sites with no UAE link get
        a scope warning; evidence lines show the actual call or sentence.
v1.4  : sites that skip their tags for automated browsers (tags set up in the code but never loaded) get a
        "manual check needed" warning, consent is marked not assessed and the grade is capped, instead of a clean
        pass; transfers described only for the EU/EEA are flagged; evidence quotes the exact sentence.
Checks the presence of required wording and observable behaviour only. Not legal advice.
"""
import argparse
import asyncio
import html
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

try:
    from playwright.async_api import async_playwright
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("Playwright is missing. Run:  pip install playwright   then   python -m playwright install chromium")

# ============================ SETTINGS YOU CAN EDIT ============================
BRAND = "SecComply"            # default "Prepared by" on the report
OUTPUT_DIR = "reports"         # folder (next to this file) where reports are saved
RULESET_DATE = "8 October 2026"
LAW = "Federal Decree-Law No. 45 of 2021 on the Protection of Personal Data (UAE PDPL)"
STATUS_NOTE = ("As at " + RULESET_DATE + ", the PDPL Executive Regulations (Art. 28) and the Cabinet decision on "
               "violations and administrative penalties (Art. 26) were not published on the official UAE "
               "Legislation portal. Controllers have six months from the issue of the Executive Regulations to "
               "comply (Art. 29). Findings are readiness gaps against the Decree-Law text, not confirmed "
               "violations, and no penalty amounts are quoted.")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/140.0.0.0 Safari/537.36")
GST = timezone(timedelta(hours=4))   # Gulf Standard Time for report dates
# Low-memory browser settings (needed for small servers such as Render's free plan)
CHROME_ARGS = ["--disable-dev-shm-usage", "--disable-gpu", "--disable-extensions", "--mute-audio",
               "--disable-site-isolation-trials", "--disable-features=site-per-process,IsolateOrigins",
               "--renderer-process-limit=2"]
# Run the Accept and Reject browser sessions side by side? "auto" = only when the server has 1.5 GB+ memory.
# Override with the SCAN_PARALLEL environment variable (1 / 0 / auto) or --parallel on the command line.
PARALLEL = os.environ.get("SCAN_PARALLEL", "auto")
SESSION_LIMIT = int(os.environ.get("SCAN_SESSION_LIMIT", "240"))   # seconds; a browser session is stopped after this
# ===============================================================================

CATS = {"consent": ("Consent & tracking", 25), "notice": ("Privacy notice", 20),
        "rights": ("Data subject rights", 15), "security": ("Security safeguards", 15),
        "cross_border": ("Cross-border transfers", 10), "collection": ("Data collection forms", 10),
        "governance": ("Breach & complaints", 5)}                       # weights add up to 100
DEDUCT = {"critical": 35, "high": 20, "medium": 10, "low": 4, "info": 0}
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
COLOR = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467",
         "info": "#175cd3", "pass": "#067647"}
BASIS = {"law": "PDPL obligation", "best": "Best practice", "advisory": "Advisory (not scored)"}
GRADES = [(80, "A", "Few observable gaps"), (60, "B", "Moderate gaps - prioritise high-severity items"),
          (40, "C", "Significant gaps - remediation plan needed"), (20, "D", "Serious gaps across several areas"),
          (0, "F", "Critical gaps - immediate action required")]

# host suffix | vendor | category | HQ country   (add new vendors as you meet them; ?? = unknown)
TRACKER_DB = """
google-analytics.com|Google Analytics|analytics|US
analytics.google.com|Google Analytics|analytics|US
googletagmanager.com|Google Tag Manager|tag_manager|US
doubleclick.net|Google Ads|advertising|US
googlesyndication.com|Google Ads|advertising|US
adtrafficquality.google|Google Ads|advertising|US
googleadservices.com|Google Ads|advertising|US
amazon-adsystem.com|Amazon Ads|advertising|US
app-measurement.com|Google Analytics for Firebase|analytics|US
fonts.googleapis.com|Google Fonts|cdn|US
fonts.gstatic.com|Google Fonts|cdn|US
gstatic.com|Google static content|cdn|US
googleapis.com|Google APIs|cdn|US
maps.googleapis.com|Google Maps|functional|US
recaptcha.net|Google reCAPTCHA|security|US
youtube.com|YouTube|social|US
ytimg.com|YouTube (images and player files)|media|US
youtube-nocookie.com|YouTube (privacy-enhanced mode)|media|US
vimeo.com|Vimeo|media|US
vimeocdn.com|Vimeo|media|US
instagram.com|Meta (Instagram)|social|US
licdn.com|LinkedIn (static content)|cdn|US
linkedin.com|LinkedIn|social|US
platform.twitter.com|X (Twitter)|social|US
pinimg.com|Pinterest (images)|cdn|US
connect.facebook.net|Meta Pixel|advertising|US
facebook.net|Meta|social|US
facebook.com|Meta|social|US
analytics.tiktok.com|TikTok Pixel|advertising|SG
snap.licdn.com|LinkedIn Insight|advertising|US
px.ads.linkedin.com|LinkedIn Insight|advertising|US
static.ads-twitter.com|X Pixel|advertising|US
t.co|X Pixel|advertising|US
hicloud.com|Huawei Dynamic Tag Manager|tag_manager|CN
analytics.twitter.com|X Pixel|advertising|US
sc-static.net|Snap Pixel|advertising|US
tr.snapchat.com|Snap Pixel|advertising|US
ct.pinterest.com|Pinterest Tag|advertising|US
redditstatic.com|Reddit Pixel|advertising|US
q.quora.com|Quora Pixel|advertising|US
bat.bing.com|Microsoft Ads UET|advertising|US
criteo.com|Criteo|advertising|FR
criteo.net|Criteo|advertising|FR
taboola.com|Taboola|advertising|US
outbrain.com|Outbrain|advertising|US
adroll.com|AdRoll|advertising|US
adsrvr.org|The Trade Desk|advertising|US
clarity.ms|Microsoft Clarity|session_replay|US
hotjar.com|Hotjar|session_replay|MT
hotjar.io|Hotjar|session_replay|MT
fullstory.com|FullStory|session_replay|US
mouseflow.com|Mouseflow|session_replay|DK
smartlook.com|Smartlook|session_replay|CZ
crazyegg.com|Crazy Egg|session_replay|US
contentsquare.net|Contentsquare|session_replay|FR
contentsquare.com|Contentsquare|session_replay|FR
quantummetric.com|Quantum Metric|session_replay|US
posthog.com|PostHog|analytics|US
omtrdc.net|Adobe Analytics|analytics|US
2o7.net|Adobe Analytics|analytics|US
demdex.net|Adobe Audience Manager|advertising|US
everesttech.net|Adobe Advertising|advertising|US
adobedtm.com|Adobe Tags|tag_manager|US
tiqcdn.com|Tealium|tag_manager|US
plausible.io|Plausible|analytics|EE
statcounter.com|StatCounter|analytics|IE
mixpanel.com|Mixpanel|analytics|US
segment.com|Segment|analytics|US
segment.io|Segment|analytics|US
amplitude.com|Amplitude|analytics|US
heapanalytics.com|Heap|analytics|US
mc.yandex.ru|Yandex Metrica|analytics|RU
cloudflareinsights.com|Cloudflare Analytics|analytics|US
vwo.com|VWO|analytics|IN
visualwebsiteoptimizer.com|VWO|analytics|IN
optimizely.com|Optimizely|analytics|US
apollo.io|Apollo.io|marketing|US
aplo-evnt.com|Apollo.io|marketing|US
zoominfo.com|ZoomInfo|marketing|US
6sc.co|6sense|marketing|US
clearbit.com|Clearbit|marketing|US
hs-scripts.com|HubSpot|marketing|US
hs-analytics.net|HubSpot|marketing|US
hs-banner.com|HubSpot|marketing|US
hsforms.net|HubSpot|marketing|US
hubspot.com|HubSpot|marketing|US
hubspot.net|HubSpot|marketing|US
hsadspixel.net|HubSpot|advertising|US
hscollectedforms.net|HubSpot|marketing|US
usemessages.com|HubSpot|chat|US
chimpstatic.com|Mailchimp|marketing|US
list-manage.com|Mailchimp|marketing|US
klaviyo.com|Klaviyo|marketing|US
onesignal.com|OneSignal|marketing|US
braze.com|Braze|marketing|US
appboycdn.com|Braze|marketing|US
clevertap.com|CleverTap|marketing|US
wzrkt.com|CleverTap|marketing|US
webengage.com|WebEngage|marketing|IN
branch.io|Branch|attribution|US
adjust.com|Adjust|attribution|DE
appsflyer.com|AppsFlyer|attribution|US
onelink.me|AppsFlyer|attribution|US
intercom.io|Intercom|chat|US
intercomcdn.com|Intercom|chat|US
zopim.com|Zendesk|chat|US
zdassets.com|Zendesk|chat|US
drift.com|Drift|chat|US
crisp.chat|Crisp|chat|FR
livechatinc.com|LiveChat|chat|PL
freshchat.com|Freshchat|chat|US
salesiq.zoho.com|Zoho SalesIQ|chat|IN
nr-data.net|New Relic|monitoring|US
newrelic.com|New Relic|monitoring|US
sentry.io|Sentry|monitoring|US
sentry-cdn.com|Sentry|monitoring|US
datadoghq.com|Datadog|monitoring|US
datadoghq-browser-agent.com|Datadog|monitoring|US
bugsnag.com|Bugsnag|monitoring|US
dynatrace.com|Dynatrace|monitoring|US
go-mpulse.net|Akamai mPulse|monitoring|US
csper.io|Csper (CSP violation reports)|monitoring|??
report-uri.com|Report URI (CSP violation reports)|monitoring|GB
hcaptcha.com|hCaptcha|security|US
challenges.cloudflare.com|Cloudflare Turnstile|security|US
cdnjs.cloudflare.com|cdnjs|cdn|US
cloudfront.net|Amazon CloudFront|cdn|US
akamaihd.net|Akamai|cdn|US
akamaized.net|Akamai|cdn|US
typekit.net|Adobe Fonts|cdn|US
jsdelivr.net|jsDelivr|cdn|??
unpkg.com|unpkg|cdn|??
cdn.shopify.com|Shopify|functional|CA
wixstatic.com|Wix|cdn|IL
parastorage.com|Wix|cdn|IL
squarespace-cdn.com|Squarespace|cdn|US
firebaseio.com|Google Firebase|functional|US
mapbox.com|Mapbox|functional|US
trustpilot.com|Trustpilot|functional|DK
wp.com|WordPress.com|cdn|US
imagekit.io|ImageKit|cdn|IN
flagcdn.com|FlagCDN|cdn|??
stripe.com|Stripe|functional|US
paypal.com|PayPal|functional|US
calendly.com|Calendly|functional|US
cookielaw.org|OneTrust|consent|US
onetrust.com|OneTrust|consent|US
cookiebot.com|Cookiebot|consent|DK
usercentrics.eu|Usercentrics|consent|DE
didomi.io|Didomi|consent|FR
privacy-center.org|Didomi|consent|FR
osano.com|Osano|consent|US
termly.io|Termly|consent|US
iubenda.com|iubenda|consent|IT
consentmanager.net|consentmanager|consent|DE
trustarc.com|TrustArc|consent|US
truste.com|TrustArc|consent|US
"""
TRACKERS = {}
for _line in TRACKER_DB.strip().splitlines():
    _host, *_meta = _line.split("|")
    TRACKERS[_host] = tuple(_meta)
TRACKER_KEYS = sorted(TRACKERS, key=len, reverse=True)
PATH_RULES = [(r"(^|\.)(google\.com|gstatic\.com)$", r"^/recaptcha/", ("Google reCAPTCHA", "security", "US")),
              (r"(^|\.)google\.[a-z.]+$", r"^/(pagead|ads|ccm|rmkt|measurement|conversion|async)/", ("Google Ads", "advertising", "US")),
              (r"(^|\.)google\.[a-z.]+$", r"^/g/collect", ("Google Analytics", "analytics", "US")),
              (r"(^|\.)google\.[a-z.]+$", r"^/maps(/|$)", ("Google Maps", "functional", "US")),
              (r"(^|\.)facebook\.com$", r"^/tr/?$", ("Meta Pixel", "advertising", "US"))]
NON_ESSENTIAL = {"advertising", "analytics", "session_replay", "social", "marketing", "attribution"}
TRACK_COOKIES = [(re.compile(p, re.I), v) for p, v in [
    (r"^_ga($|_)|^_gid$|^_gat", "Google Analytics"), (r"^(_gcl_|_gac_)|^(IDE|DSID|test_cookie|__gads|__gpi)$", "Google Ads"),
    (r"^_fb[pc]$", "Meta Pixel"), (r"^(_ttp|_tt_enable_cookie|ttcsid)", "TikTok"), (r"^(_scid|_sctr|sc_at)", "Snap"),
    (r"^(_uetsid|_uetvid|MUID)$", "Microsoft Ads"), (r"^(_clck|_clsk|CLID)$", "Microsoft Clarity"), (r"^_hj", "Hotjar"),
    (r"^(hubspotutk|__hstc|__hssc|__hssrc)$", "HubSpot"), (r"^(li_sugr|bcookie|lidc|li_fat_id|UserMatchHistory)$", "LinkedIn"),
    (r"^_pin_unauth$", "Pinterest"), (r"^mp_.*_mixpanel$", "Mixpanel"), (r"^ajs_(anonymous|user)_id$", "Segment"),
    (r"^AMP_", "Amplitude"), (r"^_ym_", "Yandex"), (r"^(personalization_id|guest_id|muc_ads)$", "X"),
    (r"^_rdt_uuid$", "Reddit"), (r"^(_fs_|fs_uid)", "FullStory"), (r"^ph_.*_posthog$", "PostHog"),
    (r"^_vwo|^_vis_opt", "VWO"), (r"^_mkto_trk$", "Marketo"), (r"^vuid$", "Vimeo"), (r"^_cs_(id|s|c)$", "Contentsquare")]]
# A vendor's script/stylesheet download is not by itself a tracking call. It counts as one only when the URL
# carries hit or identifier parameters (e.g. Google Ads JSONP conversion pings are served as scripts).
LIB_TYPES = {"script", "stylesheet", "font"}
TRACK_PARAM_RE = re.compile(r"[?&](gcs|gcd|ev|en|cid|uid|fbp|_fbp|tid|random|fst|cv|dl|dr|sid|_p|uuid|ts)=", re.I)
LIB_EXT_RE = re.compile(r"\.(m?js|css|woff2?|ttf|otf)$", re.I)
LIB_PATH_RE = re.compile(r"/signals/config/|/gtag/(js|destination)|/gtm\.js|/tag/|/sdk(\.js|/)|/pixel/(config|events|static)", re.I)
LOADER_KEYS = {"id", "v", "r", "sv", "l", "cb", "ver", "version", "render", "hl", "onload", "family", "display", "cx",
               "libraries", "key", "callback", "sdkid", "lib", "lang", "locale", "ref", "pixel_id"}
MODE_LABEL = {"tracking": "Tracking", "denied": "Pings (consent denied)", "script": "Script only"}
VERSION_RE = re.compile(r"\b[A-Za-z][\w.-]*/v?\d+(?:\.\d+)*|\bv?\d+\.\d+(?:\.\d+)*\b")  # nginx/1.18, PHP 8.1 - not "AmazonS3"
POLICY_KW = re.compile(r"personal (?:data|information)|data protection|privacy|البيانات الشخصية|حماية البيانات|الخصوصية", re.I)
SUBSTANCE = [re.compile(p, re.I) for p in (
    r"(information|data) (that )?we collect|we (may )?collect|categories of (personal )?(data|information)|البيانات التي نجمعها",
    r"\bretain|retention|how long|الاحتفاظ", r"your rights|right to|you (can|may) (request|ask)|حقوقك|يحق لك",
    r"third[- ]part|service providers?|we (may )?share|disclose|الأطراف الثالثة",
    r"purposes?|how we use|نستخدم", r"cookies?|ملفات تعريف الارتباط", r"contact us|كيفية التواصل|اتصل بنا")]
NOTICE_LINK_RE = re.compile(r"privacy|data[- ]protection|personal data|الخصوصية|حماية البيانات", re.I)
BLOCKED_RE = re.compile(r"just a moment|attention required|access denied|request blocked|are you (a )?(human|robot)|"
                        r"verify you are human|captcha|security check", re.I)
REQUEST_ROUTE_RE = re.compile(r"subject access request|data subject (access )?request|\bDSAR\b|"
                              r"\b(request|contact( us)?|rights?|privacy|enquiry|inquiry)[\w ]{0,20}\b(form|portal)s?\b|"
                              r"\b(form|portal)\b[^.]{0,60}\b(request|exercise|rights|personal data)|"
                              r"\b(write|send|submit|contact|reach|email)[^.]{0,40}\b(privacy|data protection|legal) (team|office|officer|department)|"
                              r"\b(exercise|request)[^.]{0,60}\b(contact us|write to|help ?cent(re|er))|نموذج (طلب|التواصل)", re.I)
LOCALE_SEG_RE = re.compile(r"^[a-z]{2}([-_][a-z]{2})?$", re.I)


def rx(*parts):
    return re.compile("|".join(parts), re.I)


ACCEPT_RE = rx(r"^\s*(accept|allow|agree|i agree|ok\b|okay|got it|i understand|continue|yes)", r"^\s*(قبول|موافق|أوافق|حسنا|السماح)")
REJECT_RE = rx(r"reject|decline|deny|refuse|disagree|do not (accept|agree)|don'?t (accept|agree|allow)|without accepting",
               r"(only|strictly) (necessary|essential|required)|(necessary|essential|required) (cookies )?only",
               r"accept (only )?(necessary|essential)|no,? thanks|رفض|الضرورية فقط|لا أوافق")
SAVE_RE = rx(r"allow selection|save (my )?(choices|preferences|selection|settings)|confirm (my )?choices|حفظ")
SETTINGS_RE = rx(r"settings|preferences|customi[sz]e|manage|options|choices|let me choose|الإعدادات|تخصيص|إدارة|التفضيلات")
IMPLIED_RE = rx(r"by (continuing|using|browsing|staying)|continued use|if you continue|بمواصلة|باستمرارك|باستخدامك")
NECESSARY_RE = rx(r"necessary|essential|strictly|required|ضرورية|أساسية")
PRIVACY_RE = rx(r"privacy|data protection|personal data|الخصوصية|حماية البيانات|البيانات الشخصية")
GENERIC_COMPLAINT_RE = rx(r"(lodge|file|submit|make) a complaint|supervisory authority|data protection (authority|regulator)|تقديم شكوى")
CHILD_RE = rx(r"\b(kids?|children|toddlers?|babies|nursery|kindergarten|toys?|pupils?)\b", r"\bages? \d{1,2} ?(-|to) ?\d{1,2}\b|أطفال|حضانة")
AGEGATE_RE = rx(r"are you (over|at least) \d{2}|(confirm|verify) (your )?age|age verification|enter your (date of birth|age)|تأكيد العمر")
FORMPAGE_RE = rx(r"contact|enquir|inquir|sign-?up|register|apply|career|demo|quote|subscribe|newsletter|appointment|اتصل|تواصل|تسجيل|احجز")
MARKETING_RE = rx(r"marketing|newsletter|promotional|التسويق|النشرة")
LEGIT_RE = rx(r"legitimate interests?")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
MIXED_RE = re.compile(r"<(?:script|img|iframe|source|video|audio|embed)\b[^>]*?\ssrc\s*=\s*[\"'](http://[^\"']+)", re.I)
# Lines ignored by notice checks: contents lists, definitions, unfinished placeholders
TOC_RE = re.compile(r"(?:(?:^|\s)\d{1,2}(?:\.\d{1,2})*\.?\s+[A-Z][^.\n]{0,45}){3,}")
DEF_RE = re.compile(r"^[\"'\u201c\u2018]?[A-Za-z][\w /&()-]{0,50}[\"'\u201d\u2019]?\s+(means|refers to|shall mean|has the meaning|is defined as)\b"
                    r"|^(means|refers to|shall mean)\b", re.I)
PLACEHOLDER_RE = re.compile(r"\[[^\]\n]{0,80}\b(insert|inserted|to be (added|confirmed|updated|provided)|tbd|tbc|placeholder|"
                            r"company name|your company|address here)\b[^\]\n]{0,80}\]|lorem ipsum|\{\{[^}\n]{1,40}\}\}|\bTBD\b", re.I)
UAE_REF_RE = rx(r"\bUAE PDPL\b|45 of 2021|decree[- ]law no\.? ?\(?45|uae (personal )?data protection law|uae data office",
                r"(united arab emirates|\buae\b)[^.]{0,40}\b(personal data protection|data protection) (law|legislation|regulation|decree)",
                r"المرسوم بقانون اتحادي رقم ?\(?45|مكتب الإمارات للبيانات")
FOREIGN_LAWS = [
    ("India's DPDP Act", r"\bDPDP\b|Digital Personal Data Protection|Data Protection Board of India|Data Fiduciar|Data Principal"
                         r"|Grievance Officer|Companies Act,? 2013|SPDI Rules|Information Technology Act"),
    ("the EU GDPR", r"\bGDPR\b|General Data Protection Regulation|\bEEA\b|European Economic Area|EU standard contractual"),
    ("the UK GDPR", r"\bUK GDPR\b|Data Protection Act 2018|Information Commissioner"),
    ("US state privacy laws", r"\bCCPA\b|\bCPRA\b|California Consumer Privacy"),
    ("Saudi Arabia's PDPL", r"\bSDAIA\b|Saudi Data (and|&) (AI|Artificial Intelligence) Authority")]
PROBE = ["/privacy-policy", "/privacy", "/privacy-notice", "/legal/privacy", "/policies/privacy-policy",
         "/pages/privacy-policy", "/en/privacy-policy", "/ar/privacy-policy"]
UAE_PATH_RE = re.compile(r"^/(ae|uae|en-ae|ar-ae|ae-en|ae-ar)(/|$)", re.I)
PII = {k: re.compile(v, re.I) for k, v in [
    ("email", r"e-?mail|البريد"), ("phone", r"phone|mobile|\btel\b|whatsapp|هاتف|جوال"),
    ("name", r"\bname\b|fullname|full_name|first.?name|last.?name|surname|الاسم"),
    ("address", r"address|street|po.?box|العنوان"), ("date_of_birth", r"birth|\bdob\b|تاريخ الميلاد"),
    ("emirates_id", r"emirates.?id|\beid\b|national.?id|الهوية"), ("passport", r"passport|جواز"),
    ("payment", r"card.?number|cc-number|\bcvv\b|\biban\b"), ("nationality", r"nationality|الجنسية"),
    ("salary", r"salary|income|الراتب")]}
SENS = {k: re.compile(v, re.I) for k, v in [                     # PDPL Art. 1 "Sensitive Personal Data"
    ("health", r"health|medical|diagnos|blood|allerg|disabilit|pregnan|medication|صحي|طبي"),
    ("religion", r"religio|\bfaith\b|\bsect\b|الدين|الديانة"),
    ("family", r"marital|spouse|husband|\bwife\b|number.?of.?children|dependents|الحالة الاجتماعية"),
    ("ethnic_origin", r"ethnic|\brace\b|العرق"), ("criminal_record", r"criminal|conviction|police.?clearance|good.?conduct"),
    ("biometric", r"biometric|fingerprint|face.?id|selfie|liveness|البصمة"), ("political_opinion", r"political|سياسي")]}

# (id, category, severity if missing, basis, reference, title, [patterns - all must match], fix)
CHECKS = [
    ("N-PURPOSE", "notice", "high", "law", "Art. 13(1)(b), 13(2); Art. 5(2)", "Purposes of processing",
     [r"purposes? (of|for) (which|the processing|processing|collect|using)|we (use|process)[^.]{0,40}(data|information)[^.]{0,30}\b(to|for)\b|how we use|why we (collect|use|process)|الأغراض|الغرض من|نستخدم"],
     "List each purpose of processing. Art. 13(2) requires this before processing starts."),
    ("N-TYPES", "notice", "medium", "law", "Art. 13(1)(a)", "Types of personal data processed",
     [r"(information|data) (that )?we collect|types? of (personal )?(data|information)|categories of (personal )?(data|information)|we (may )?collect|البيانات التي نجمعها|المعلومات التي نجمعها"],
     "List the categories of personal data collected (identity, contact, online identifiers, transactions)."),
    ("N-RECIPIENTS", "notice", "high", "law", "Art. 13(1)(d), 13(2)", "Recipients and sharing (inside and outside the UAE)",
     [r"we (may )?(share|disclose)|(share|shared|disclose|disclosed)[^.]{0,30}\bwith\b|third[- ]part(y|ies)|service providers?|recipients? of|الأطراف الثالثة|طرف ثالث|نشارك|مزودي الخدمات"],
     "Name the categories of recipients inside and outside the UAE. Required before processing (Art. 13(2))."),
    ("X-TRANSFER", "cross_border", "high", "law", "Art. 13(1)(g), 13(2); Art. 22-23", "Cross-border transfers and safeguards",
     [r"outside (of )?(the )?(uae|u\.a\.e|united arab emirates|state|country)|international(ly)? transfer|cross[- ]border|transfer(red|s)?[^.]{0,80}(countr|jurisdiction|abroad)|transfer(red|s|ring)?[^.]{0,60}\boutside\b|(located|stored|hosted|processe?d?)[^.]{0,30}\boutside (of )?(the )?[a-z]{3,}|contractual clauses|خارج الدولة|خارج (دولة )?الإمارات|عبر الحدود"],
     "State the destination countries and the safeguard used: a Data Office-approved country (Art. 22) or a contract / explicit consent (Art. 23)."),
    ("N-RETENTION", "notice", "medium", "law", "Art. 13(1)(e); Art. 5(7)", "Retention period or criteria",
     [r"\bretain|retention|how long|keep (your |the )?(personal )?(data|information)|(stored|kept) for|الاحتفاظ|مدة (التخزين|الحفظ)"],
     "State retention periods or criteria, and deletion or anonymisation when the purpose ends."),
    ("N-AUTOMATED", "notice", "low", "law", "Art. 13(1)(c); Art. 18", "Automated decisions and profiling",
     [r"automated (decision|processing|means|individual)|decisions? (based|made)[^.]{0,30}automat|profiling (of|about) you|we (do not |don't )?(use|carry out|engage in|conduct) profiling|التنميط|المعالجة الآلية"],
     "Say whether automated decisions or profiling are used, and how to object or request human review."),
    ("N-BASIS", "notice", "medium", "law", "Art. 4; Art. 5(1)", "Legal basis (consent or an Art. 4 exception)",
     [r"legal basis|lawful basis|basis (for|of) (the |our )?processing|(based|rely|relies) on (your )?consent|with your consent|necessary (for|to) (the )?perform|الأساس القانوني|بموافقتك"],
     "State the basis for each purpose: consent, or a specific Art. 4 exception such as contract (Art. 4(9)). The PDPL has no legitimate-interests ground."),
    ("N-IDENTITY", "notice", "medium", "best", "Best practice; supports Art. 19", "Company identity and address",
     [r"\b(l\.?l\.?c|fz-?llc|fze|fzco|pjsc|dmcc|ltd|inc|plc|private limited|pvt\.? ltd)\b|registered (office|address)|data controller|p\.?\s?o\.? box|ش\.ذ\.م\.م|المتحكم|صندوق بريد"],
     "Name the legal entity responsible for the data and its registered address."),
    ("N-COOKIES", "notice", "low", "best", "Best practice; supports Art. 13(1)(a)-(b)", "Cookies and trackers explained",
     [r"cookie|similar technologies|pixels?|ملفات تعريف الارتباط|الكوكيز"],
     "Explain the cookies, pixels and SDKs used, by vendor and purpose, and how to change choices."),
    ("N-UPDATED", "notice", "low", "best", "Best practice", "Last-updated date",
     [r"last (updated|revised|modified|reviewed)|effective (date|from|as of)|updated (on|as of)|آخر تحديث|تاريخ السريان"],
     "Show a 'last updated' date on the notice."),
    ("N-SENSITIVE", "collection", "low", "law", "Art. 1 (Sensitive Personal Data); Art. 10(1)(c); Art. 21(2)(b)", "Sensitive personal data handling",
     [r"sensitive (personal )?(data|information)|special categor|health (data|information)|biometric|البيانات (الشخصية )?الحساسة"],
     "Explain which sensitive data is processed, why, and the extra safeguards and consent applied."),
    ("R-ERASURE", "rights", "high", "law", "Art. 13(1)(f); Art. 15", "Correction and erasure rights",
     [r"(correct|rectif|amend|update)[^.]{0,60}(data|information)|(data|information)[^.]{0,40}\b(corrected|rectified|amended|updated)\b|\brectification\b|right (to|of) (correction|rectification)|تصحيح",
      r"(delet|eras)[^.]{0,60}(data|information)|(data|information)[^.]{0,40}\b(deleted|erased)\b|right (to|of) (erasure|deletion)|حذف|محو"],
     "Explain how to request correction and erasure, and when erasure applies (Art. 15)."),
    ("R-RESTRICT", "rights", "medium", "law", "Art. 16; Art. 17", "Restriction and objection rights",
     [r"restrict(ion)?[^.]{0,30}processing|\bobject(ion)?\b[^.]{0,30}processing|stop (the )?processing|تقييد|الاعتراض"],
     "Explain the rights to restrict processing (Art. 16) and to object to or stop it (Art. 17)."),
    ("R-PORTABILITY", "rights", "low", "law", "Art. 14", "Data portability",
     [r"portab|machine[- ]readable|structured,? (commonly used|format)|نقل البيانات|قابلية النقل"],
     "Explain the right to receive data in a machine-readable format and have it sent to another company."),
    ("R-MARKETING", "rights", "medium", "law", "Art. 17(1)", "Right to stop direct marketing",
     [r"unsubscribe|direct marketing|marketing (communications|emails|messages|material)|opt[- ]?out of (marketing|promotional|newsletter)|promotional (emails|messages|communications)|إلغاء الاشتراك|التسويق المباشر"],
     "Explain how to stop direct marketing at any time, across email, SMS and WhatsApp."),
    ("C-WITHDRAW-TEXT", "consent", "high", "law", "Art. 6(1)(c), 6(2)", "How to withdraw consent",
     [r"withdraw[^.]{0,30}consent|revoke[^.]{0,30}consent|withdrawal of (your )?consent|سحب (الموافقة|موافقتك)"],
     "Explain that consent can be withdrawn at any time, and how."),
    ("G-BREACH", "governance", "medium", "law", "Art. 13(1)(h); Art. 9", "Breach handling",
     [r"(data|security|personal data) breach|security incident|اختراق|خرق|حادث(ة)? أمني"],
     "Describe what happens if personal data is breached, including notifying affected people and the Data Office."),
    ("G-COMPLAINT", "governance", "medium", "law", "Art. 13(1)(i); Art. 24", "Complaint route to the UAE Data Office",
     [r"(uae )?data office|مكتب الإمارات للبيانات|مكتب البيانات"],
     "Tell people they can complain to the UAE Data Office (Art. 24)."),
    ("G-DPO", "governance", "info", "law", "Art. 10; Art. 12(2)", "Data Protection Officer contact",
     [r"data protection officer|\bDPO\b|مسؤول حماية البيانات"],
     "Appoint and publish a DPO if an Art. 10(1) trigger applies (high-risk technology or volume, sensitive data at scale)."),
]
CHECKS = [(c[0], c[1], c[2], c[3], ("PDPL " + c[4]) if c[3] == "law" else c[4], c[5],
           [re.compile(p, re.I) for p in c[6]], c[7]) for c in CHECKS]
FULL_SCOPE = {"N-UPDATED", "N-IDENTITY", "G-DPO", "N-COOKIES"}   # may sit in short lines, so search all clean lines
# When a check passes, quote a line that also contains these words if there is one (better evidence, same result)
PREFER = {"N-RECIPIENTS": re.compile(r"\b(share|shares|shared|sharing|disclose|disclosed|disclosure|recipients?)\b|نشارك", re.I),
          "N-PURPOSE": re.compile(r"\bpurposes?\b|how we use|الأغراض", re.I),
          "N-RETENTION": re.compile(r"\b(retain|retention|store)\b|الاحتفاظ", re.I),
          "N-BASIS": re.compile(r"legal basis|lawful basis|legitimate use|\bconsent\b|الأساس القانوني", re.I)}
# Strong signs in the page code that a tracking tag is set up: (label, pattern, vendor names that prove it loaded)
TAG_SIGNS = [
    ("Google Tag Manager", r"\bGTM-[A-Z0-9]{4,10}\b", ("Google Tag Manager", "Google tag loader via the site's own server")),
    ("Google tag (gtag)", r"gtag\(\s*['\"]config['\"]\s*,\s*['\"](?:G|AW|DC)-[A-Z0-9]+", ("Google Tag Manager", "Google Analytics", "Google Ads",
                                                                           "Google tag loader via the site's own server", "Google Analytics via the site's own server")),
    ("Meta Pixel", r"fbq\(\s*['\"]init['\"]", ("Meta Pixel", "Meta")),
    ("LinkedIn Insight", r"_linkedin_partner_id", ("LinkedIn Insight",)),
    ("Microsoft Clarity", r"clarity\.ms/tag/", ("Microsoft Clarity",)),
    ("Hotjar", r"static\.hotjar\.com/c/hotjar-|_hjSettings", ("Hotjar",)),
    ("TikTok Pixel", r"ttq\.load\(", ("TikTok Pixel",)),
    ("Microsoft Ads UET", r"bat\.bing\.com/bat\.js|\buetq\b", ("Microsoft Ads UET",)),
    ("X Pixel", r"\btwq\(\s*['\"](?:init|config)", ("X Pixel",))]
TAG_SIGNS = [(lab, re.compile(p), names) for lab, p, names in TAG_SIGNS]


def tags_in_code(page_html):
    """Tracking tags set up in the page code (ignoring CSP and link tags, which only name allowed hosts)."""
    code = re.sub(r"<meta\b[^>]*>|<link\b[^>]*>", " ", page_html or "", flags=re.I)
    found = []
    for lab, rxp, names in TAG_SIGNS:
        m = rxp.search(code)
        if m:
            found.append((lab, m.group(0)[:40], names))
    return found


PD_RE = re.compile(r"personal (data|information)|your (data|information)|البيانات الشخصية", re.I)
DATE_RE = re.compile(r"\b(19|20)\d{2}\b|\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b", re.I)

NOT_COVERED = ["Records of processing (Art. 7(4)) and processor contracts (Art. 8)",
               "Proof-of-consent records (Art. 6(1)(a))", "Breach-notification procedure (Art. 9)",
               "DPO appointment and Data Office notification (Art. 10-12)",
               "DPIAs (Art. 21) and internal security controls (Art. 20)",
               "Back-end transfers abroad: hosting, CRM, email and support tools (Art. 22-23)",
               "Pages behind logins, mobile apps, and email/SMS/WhatsApp marketing"]
LIMITS = ["Clean browser sessions are captured before consent, after 'Accept' and after 'Reject'; every third-party "
          "request is matched to a vendor database with headquarters country. Requests caused by the 'Accept' or "
          "'Reject' click itself are attributed to that choice, not to the pre-consent state. In each session the page is "
          "scrolled and the mouse moved like a visitor reading it, because many sites load their tags only on the first "
          "interaction; scrolling is not consent.",
          "A vendor counts as tracking when it makes data-sending calls or sets tracking cookies. A vendor whose "
          "script is only downloaded is shown as 'Script only'; Google Consent Mode calls marked as denied are shown "
          "separately. Cookies already set before 'Reject' are reported as left in place, not as new tracking.",
          "Where the privacy link leads to a page listing several notices, the notices it links to are read together. "
          "Privacy notices published as PDF files are read as well.",
          "Privacy-notice checks read only the main policy text (menus, contents lists and definitions are ignored) "
          "and look for required wording in English and Arabic; they do not judge legal adequacy.",
          "Results reflect what the scanner's location was shown; banners can differ for UAE visitors.",
          "Vendor HQ country indicates where data may go; actual locations depend on vendor contracts.",
          "Automated banner clicks can fail on unusual consent tools; such checks are listed as not covered."]

FP_JS = r"""(() => { if (window.__fp) return; const hits = [], seen = new Set(); window.__fp = hits;
 const src = () => { try { for (const l of (new Error().stack || '').split('\n').slice(3)) { const m = l.match(/(https?:\/\/[^\s()]+?):\d+:\d+/); if (m) return m[1]; } } catch (e) {} return ''; };
 const wrap = (c, p, api) => { try { const pr = window[c] && window[c].prototype, o = pr && pr[p]; if (typeof o !== 'function') return;
   Object.defineProperty(pr, p, { configurable: true, writable: true, value: function (...a) {
     if (hits.length < 300) { const s = src(), k = api + s; if (!seen.has(k)) { seen.add(k); hits.push({ api, src: s }); } }
     return o.apply(this, a); } }); } catch (e) {} };
 wrap('HTMLCanvasElement', 'toDataURL', 'canvas'); wrap('HTMLCanvasElement', 'toBlob', 'canvas');
 wrap('CanvasRenderingContext2D', 'getImageData', 'canvas'); wrap('WebGLRenderingContext', 'getParameter', 'webgl');
 wrap('WebGL2RenderingContext', 'getParameter', 'webgl'); wrap('OfflineAudioContext', 'startRendering', 'audio'); })();"""

# text = whole page (used for UAE signals); main = main content without menus/header/footer (used for notice checks)
PAGE_JS = r"""() => { const LAYOUT = 'nav,header,footer,aside,[role="navigation"],[role="banner"],[role="contentinfo"]';
 const BANNER = '[role="dialog"],[role="alertdialog"],[aria-modal="true"],#onetrust-consent-sdk,#CybotCookiebotDialog,#usercentrics-root,.cky-consent-container,[id*="cookie-banner" i],[class*="cookie-banner" i],[id*="cookie-consent" i],[class*="cookie-consent" i],[id*="consent-banner" i],[class*="consent-banner" i]';
 const exc = [...document.querySelectorAll(LAYOUT)].concat([...document.querySelectorAll(BANNER)].filter(e => (e.innerText || '').length < 6000));
 const drop = new Set(); exc.forEach(e => (e.innerText || '').split('\n').forEach(l => { l = l.trim(); if (l) drop.add(l); }));
 const cands = [...document.querySelectorAll('main,article,[role="main"]')].filter(e => (e.innerText || '').length > 600 && !exc.some(x => x !== e && x.contains(e)))
   .sort((a, b) => (b.innerText || '').length - (a.innerText || '').length);
 const root = cands[0] || document.body;
 const main = root ? (root.innerText || '').split('\n').map(l => l.trim()).filter(l => l && !drop.has(l)).join('\n') : '';
 const lk = a => ({ text: (a.innerText || a.getAttribute('aria-label') || a.getAttribute('title') || '').trim().replace(/\s+/g, ' ').slice(0, 80), href: a.href });
 return { lang: document.documentElement.lang || '', title: document.title || '',
  links: [...document.querySelectorAll('a[href]')].slice(0, 2000).map(lk).filter(l => /^(https?|mailto):/i.test(l.href)),
  langs: [...document.querySelectorAll('a,button,[role="button"],[role="option"],[role="menuitem"],li,span,div')].filter(e => e.children.length === 0 || e.tagName === 'A' || e.tagName === 'BUTTON').map(e => (e.innerText || e.textContent || '').trim()).filter(t => /^(العربية|عربي|arabic)$/i.test(t)).slice(0, 3),
  mlinks: root ? [...root.querySelectorAll('a[href]')].slice(0, 600).filter(a => !exc.some(x => x.contains(a))).map(lk).filter(l => /^https?:/i.test(l.href)) : [],
  alts: [...document.querySelectorAll('link[rel="alternate"][hreflang]')].map(l => ({ lang: l.hreflang, href: l.href })),
  text: (document.body ? document.body.innerText : '').slice(0, 200000), main: main.slice(0, 200000),
  html: document.documentElement.outerHTML.slice(0, 600000) }; }"""

BANNER_JS = r"""() => {
 const KW = /(cookie|consent|gdpr|ملفات تعريف الارتباط|ملفات الارتباط|الكوكيز)/i;
 const SEL = '[id*="cookie" i],[class*="cookie" i],[id*="consent" i],[class*="consent" i],[id*="gdpr" i],[id*="onetrust" i],[id*="cybot" i],[id*="didomi" i],[id^="cmp" i],[id*="usercentrics" i],[aria-label*="cookie" i],[aria-label*="consent" i],[role="dialog"],[role="alertdialog"],[aria-modal="true"]';
 const KNOWN = '#onetrust-banner-sdk,#onetrust-consent-sdk,#CybotCookiebotDialog,#usercentrics-root,.cky-consent-container,#didomi-host,#cmpbox,#cmpwrapper,.cmplz-cookiebanner,.osano-cm-window,#truste-consent-track,#cookie-law-info-bar,.cc-window,#iubenda-cs-banner,#termly-code-snippet-support';
 const STOP = new Set(['BODY', 'HTML', 'MAIN', 'HEADER', 'FOOTER', 'NAV', 'ARTICLE', 'ASIDE']);
 const roots = [document]; const walk = r => { for (const el of r.querySelectorAll('*')) if (el.shadowRoot) { roots.push(el.shadowRoot); walk(el.shadowRoot); } };
 try { walk(document); } catch (e) {}
 const vis = el => { const b = el.getBoundingClientRect(), s = getComputedStyle(el); return b.width > 0 && b.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && parseFloat(s.opacity || '1') > 0.05; };
 const ACT = /accept|agree|allow|reject|decline|deny|refuse|ok\b|got it|settings|preferences|manage|customi[sz]e|necessary|essential|continue without|قبول|رفض|موافق|أوافق|الإعدادات/i;
 const isCtrl = b => vis(b) && (b.tagName !== 'A' || ACT.test(b.innerText || b.getAttribute('aria-label') || ''));
 const ctrls = el => [...el.querySelectorAll('button,[role="button"],a,input[type="button"],input[type="submit"]')].filter(isCtrl).length;
 const floating = el => { for (let e = el, k = 0; e && k < 5 && !STOP.has(e.tagName); e = e.parentElement, k++) { const s = getComputedStyle(e);
   if (s.position === 'fixed' || s.position === 'sticky' || e.getAttribute('role') === 'dialog' || e.getAttribute('aria-modal') === 'true') return true; } return false; };
 const inView = el => { const b = el.getBoundingClientRect(); return b.top < innerHeight && b.bottom > 0; };
 const boxes = []; for (const r of roots) for (const el of r.querySelectorAll(SEL)) { if (!vis(el)) continue; const t = (el.innerText || '').trim();
  if (!t || t.length < 30 || t.length > 6000 || !KW.test(t)) continue;           // a short "Cookie Policy" link is not a banner
  const byAttr = el.matches('[id*="cookie" i],[class*="cookie" i],[id*="consent" i],[class*="consent" i],[id*="gdpr" i],[id*="onetrust" i],[id*="cybot" i],[id*="didomi" i],[id^="cmp" i],[id*="usercentrics" i],[aria-label*="cookie" i],[aria-label*="consent" i]') || el.closest(KNOWN);
  if (!byAttr && !/cookie|ملفات تعريف الارتباط|ملفات الارتباط|الكوكيز/i.test(t)) continue;   // e.g. a newsletter pop-up
  if (STOP.has(el.tagName)) continue;
  let box = el; for (let k = 0; k < 3 && box && !ctrls(box); k++) { const p = box.parentElement; box = (p && !STOP.has(p.tagName) && (p.innerText || '').length < 3000) ? p : null; }
  if (!box || !ctrls(box) || boxes.includes(box)) continue;
  // a banner floats over the page, is a known consent tool, or sits in view with consent buttons - not a footer note
  if (!(box.matches(KNOWN) || box.closest(KNOWN) || floating(box) || (inView(box) && /accept|agree|allow|consent|قبول|موافق/i.test(box.innerText || '')))) continue;
  boxes.push(box); }
 const seen = new Set(), buttons = [], pre = []; let text = '', i = 0;
 for (const c of boxes) { const t = (c.innerText || '').trim(); if (t.length > text.length) text = t;
  for (const b of c.querySelectorAll('button,[role="button"],a,input[type="button"],input[type="submit"]')) {
   if (seen.has(b) || !vis(b) || (b.tagName === 'A' && !isCtrl(b) && !/cookie|privacy|policy/i.test(b.innerText || ''))) continue; seen.add(b);
   const lab = String(b.innerText || b.value || b.getAttribute('aria-label') || '').trim().replace(/\s+/g, ' ');
   if (!lab || lab.length > 80) continue; b.setAttribute('data-pdpl-btn', String(i)); buttons.push({ idx: i, text: lab }); i++; }
  for (const x of c.querySelectorAll('input[type="checkbox"],[role="switch"],[role="checkbox"]')) {
   if (seen.has(x)) continue; seen.add(x);
   const on = x.checked === true || x.getAttribute('aria-checked') === 'true';
   if (!on || x.disabled || x.getAttribute('aria-disabled') === 'true') continue; const h = x.closest('label,li,div');
   pre.push(((x.labels && x.labels[0] && x.labels[0].innerText) || x.getAttribute('aria-label') || (h ? h.innerText : '') || '').trim().replace(/\s+/g, ' ').slice(0, 100)); } }
 let cmp = ''; try { cmp = window.OneTrust ? 'OneTrust' : window.Cookiebot ? 'Cookiebot' : window.Didomi ? 'Didomi' : window.UC_UI ? 'Usercentrics' : document.querySelector('.cky-consent-container') ? 'CookieYes' : window.Osano ? 'Osano' : (typeof window.__tcfapi === 'function') ? 'IAB TCF CMP' : ''; } catch (e) {}
 return { found: boxes.length > 0, text: text.slice(0, 800), buttons, pre, cmp }; }"""

WITHDRAW_JS = r"""() => { const RX = /(cookies? (settings|preferences|choices)|manage (cookies|consent|preferences)|privacy (settings|choices|preferences)|consent (settings|preferences)|your privacy choices|إعدادات (ملفات تعريف الارتباط|الخصوصية|الكوكيز))/i;
 for (const el of document.querySelectorAll('a,button,[role="button"]')) { const t = (el.innerText || el.getAttribute('aria-label') || '').trim(); if (t && t.length < 80 && RX.test(t)) return t; }
 const w = document.querySelector('#ot-sdk-btn-floating,#ot-sdk-btn,.ot-sdk-show-settings,#CookiebotWidget,.cky-btn-revisit-wrapper,.osano-cm-widget,.cmplz-manage-consent,#usercentrics-root,a[href*="Cookiebot.renew"],.cc-revoke,#cookie-law-info-again,.iubenda-tp-btn,#termly-code-snippet-support,[id*="cookie-settings" i],[class*="cookie-settings" i],[class*="consent-settings" i]');
 return w ? ('widget: ' + (w.id || String(w.className) || w.tagName)) : null; }"""

# On the cookie policy page only real controls count (buttons, script links), not links to browser help pages
WITHDRAW_BTN_JS = r"""() => { const RX = /(cookie|consent|privacy) (settings|preferences|choices)|manage (cookies|consent|preferences)|change (your )?(cookie )?(settings|preferences|consent)|withdraw (my )?consent|إعدادات/i;
 for (const el of document.querySelectorAll('button,[role="button"],a[href^="#"],a[href^="javascript"],a[onclick]')) { const t = (el.innerText || el.getAttribute('aria-label') || '').trim(); if (t && t.length < 80 && RX.test(t)) return t; }
 return null; }"""
WIDGET_JS = r"""() => { const w = document.querySelector('#ot-sdk-btn-floating,#ot-sdk-btn,.ot-sdk-show-settings,#CookiebotWidget,.cky-btn-revisit-wrapper,.osano-cm-widget,.cmplz-manage-consent,a[href*="Cookiebot.renew"],.cc-revoke,#cookie-law-info-again,.iubenda-tp-btn,#termly-code-snippet-support');
 return w ? ('widget: ' + (w.id || String(w.className) || w.tagName)) : null; }"""
PLINK_JS = r"""() => [...document.querySelectorAll('a[href]')].some(a => /privacy|data-protection|الخصوصية|حماية البيانات/i.test((a.innerText || '') + ' ' + (a.getAttribute('href') || '')))"""
SGTM_LOADER_RE = re.compile(r"/(gtm\.js|gtag/js)$", re.I)          # Google tag loaders served from the site's own domain
SGTM_HIT_RE = re.compile(r"(^|/)(g|j|mp)/collect$", re.I)            # Google Analytics hits via server-side tagging

FORMS_JS = r"""() => { const SKIP = new Set(['hidden', 'submit', 'button', 'reset', 'image']);
 const plink = [...document.querySelectorAll('a[href]')].some(a => /privacy|data-protection|الخصوصية|حماية البيانات/i.test((a.innerText || '') + ' ' + (a.getAttribute('href') || '')));
 const vis = el => { const b = el.getBoundingClientRect(); return b.width > 0 && b.height > 0; }; const groups = new Map();
 for (const el of document.querySelectorAll('input,select,textarea')) { if (SKIP.has((el.getAttribute('type') || '').toLowerCase())) continue;
  const root = el.closest('form') || el.closest('[role="form"],section,[class*="form" i]') || el.parentElement; if (!root) continue;
  if (!groups.has(root)) groups.set(root, []); groups.get(root).push(el); }
 const out = []; for (const [root, els] of groups) {
  const fields = els.map(el => { let label = ''; try { if (el.labels && el.labels.length) label = el.labels[0].innerText || ''; } catch (e) {}
   return { type: (el.getAttribute('type') || el.tagName).toLowerCase(), name: el.name || '', id: el.id || '', ph: el.getAttribute('placeholder') || '',
    ac: el.getAttribute('autocomplete') || '', aria: el.getAttribute('aria-label') || '', label: label.trim().replace(/\s+/g, ' ').slice(0, 120),
    checked: !!el.checked, vis: vis(el) }; }).filter(f => f.vis || f.type === 'checkbox');
  if (!fields.length) continue; const pt = root.parentElement ? (root.parentElement.innerText || '') : '';
  out.push({ action: (root.tagName === 'FORM' && root.getAttribute('action')) ? root.action : '', fields, plink, text: (root.innerText || '').slice(0, 2500),
   ctx: pt.length < 3000 ? pt : '', links: [...root.querySelectorAll('a[href]')].slice(0, 30).map(a => ({ text: (a.innerText || '').trim().slice(0, 60), href: a.href })) }); }
 return out; }"""

CMP_SEL = {"accept": ["#onetrust-accept-btn-handler", "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
                      "#didomi-notice-agree-button", "[data-testid='uc-accept-all-button']", ".cky-btn-accept",
                      ".cmplz-accept", ".osano-cm-accept-all", "#truste-consent-button"],
           "reject": ["#onetrust-reject-all-handler", "#CybotCookiebotDialogBodyButtonDecline",
                      "#didomi-notice-disagree-button", "[data-testid='uc-deny-all-button']", ".cky-btn-reject",
                      ".cmplz-deny", ".osano-cm-denyAll", "#truste-consent-required"]}
EMPTY = {"lang": "", "title": "", "links": [], "mlinks": [], "langs": [], "alts": [], "text": "", "main": "", "html": ""}
STABLE_JS = "() => (document.body ? document.body.innerText.length : 0) + ':' + document.querySelectorAll('input,select,textarea,a[href]').length"
IMG_RE = re.compile(r"\.(png|jpe?g|gif|webp|avif|svg|ico|bmp)(\?|#|$)", re.I)
MEDIA_RE = re.compile(r"\.(mp4|webm|ogv|mov|m4v|mp3|woff2?|ttf|otf|eot)(\?|#|$)", re.I)


@dataclass
class F:
    id: str
    cat: str
    sev: str
    title: str
    basis: str
    ref: str
    evidence: str
    fix: str = ""
    passed: bool = False


# ------------------------------------------------------------------ helpers
def host_of(u):
    try:
        return (urlparse(u).hostname or "").lower()
    except ValueError:
        return ""


def site_of(h):
    p = (h or "").lower().strip(".").split(".")
    if len(p) >= 3 and p[-2] in ("co", "com", "net", "org", "gov", "ac", "edu", "sch", "mil") and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def classify(url):
    h, path = host_of(url), urlparse(url).path or "/"
    for hr, pr, meta in PATH_RULES:
        if re.search(hr, h) and re.search(pr, path):
            return meta
    for k in TRACKER_KEYS:
        if h == k or h.endswith("." + k):
            return TRACKERS[k]
    if re.search(r"(^|\.)google\.[a-z.]+$", h):
        if re.search(r"[?&](gcs|gcd)=", url):
            return ("Google Ads", "advertising", "US")  # any other Google tag hit (carries Consent Mode parameters)
        return ("Google (other services)", "functional", "US")
    return None


def snip(text, m, pad=90):
    return "..." + re.sub(r"\s+", " ", text[max(0, m.start() - pad):m.end() + pad]).strip() + "..."


def find_best(r, lines):
    """Return (line, match) for the line with the most hits, then the longest - so the evidence is the paragraph
    that is about the topic, not a passing mention (e.g. 'third parties' in an indemnity clause)."""
    best, key = None, None
    for ln in lines:
        m = r.search(ln)
        if not m:
            continue
        k = (min(5, sum(1 for _ in r.finditer(ln))), len(ln))
        if best is None or k > key:
            best, key = (ln, m), k
    return best


def ev_of(hit):
    return snip(hit[0], hit[1])


def best_sentence(rxp, lines, extra=()):
    """The sentence (not just the line) that matches rxp and every pattern in extra; returns (sentence, match) or None."""
    cands = []
    for ln in lines:
        for sn in re.split(r"(?<=[.!?;])\s+", ln):
            m = rxp.search(sn)
            if m and all(x.search(sn) for x in extra):
                cands.append((sn, m))
    return max(cands, key=lambda c: (min(5, len(rxp.findall(c[0]))), min(len(c[0]), 300))) if cands else None


async def jseval(pg, js, default=None, timeout=20):
    try:
        return await asyncio.wait_for(pg.evaluate(js), timeout)
    except Exception:
        return default


async def frames_eval(pg, js):
    out = []
    for fr in list(pg.frames):
        try:
            r = await asyncio.wait_for(fr.evaluate(js), 15)
            if isinstance(r, list):
                out += r
        except Exception:
            pass
    return out


async def settle_net(pg, net, min_ms, quiet_ms=1500, max_ms=None):
    """Wait for the page load event, then until third-party requests go quiet (at least min_ms, at most max_ms).
    Replaces 'networkidle' + a fixed sleep: busy sites with polling never reach networkidle, so the old wait
    always ran to its full timeout."""
    max_ms = max_ms or (min_ms + 6000)
    try:
        await pg.wait_for_load_state("load", timeout=max_ms)
    except Exception:
        pass
    t_load = time.monotonic()                    # the minimum and maximum both count from the load event
    while True:
        now = time.monotonic()
        if (now - t_load) * 1000 >= max_ms:
            break
        if (now - t_load) * 1000 >= min_ms and (now - net["last3p"]) * 1000 >= quiet_ms:
            break
        await asyncio.sleep(0.25)


INTERACT_JS = r"""() => { for (const t of ['touchstart', 'scroll', 'mousemove']) { try { window.dispatchEvent(new Event(t)); document.dispatchEvent(new Event(t)); } catch (e) {} } }"""


async def interact(pg, net, min_ms):
    """Move the mouse and scroll like a visitor reading the page, then wait for third-party requests to settle.
    Many sites load their tag manager only on the first scroll or mouse move. Scrolling is not consent, so
    anything that loads now still counts as 'before consent'."""
    async def gestures():
        for x, y in ((320, 300), (700, 460), (980, 260)):
            await pg.mouse.move(x, y, steps=5)
        await pg.mouse.wheel(0, 700)
        await asyncio.sleep(0.35)
        await pg.mouse.wheel(0, 700)
        await asyncio.sleep(0.35)
    try:
        await asyncio.wait_for(gestures(), 15)
        await jseval(pg, INTERACT_JS)
        await jseval(pg, "() => window.scrollTo(0, Math.max(document.body ? document.body.scrollHeight : 0, 2000))")
        await asyncio.sleep(0.6)
        await jseval(pg, "() => window.scrollTo(0, 0)")
    except Exception:
        pass
    await settle_net(pg, net, max(1500, min_ms - 1000), max_ms=min_ms + 5000)


async def settle_dom(pg, min_ms=700, max_ms=4500):
    """For text-only pages (privacy notice, form pages): wait until the visible text and form fields stop changing."""
    try:
        await pg.wait_for_load_state("load", timeout=max_ms)
    except Exception:
        pass
    t0, last, same = time.monotonic(), None, 0
    while (time.monotonic() - t0) * 1000 < max_ms:
        await asyncio.sleep(0.3)
        cur = await jseval(pg, STABLE_JS)
        if cur is not None and cur == last and (time.monotonic() - t0) * 1000 >= min_ms:
            same += 1
            if same >= 2:
                break
        else:
            same = 0
        last = cur


def kind_of(text):
    for k, r in (("reject", REJECT_RE), ("save", SAVE_RE), ("accept", ACCEPT_RE), ("settings", SETTINGS_RE)):
        if r.search(text):
            return k
    return "other"


async def detect_banner(pg):
    frames, res = list(pg.frames), {"found": False, "text": "", "buttons": [], "pre": [], "cmp": ""}
    for i, fr in enumerate(frames):
        try:
            r = await asyncio.wait_for(fr.evaluate(BANNER_JS), 15)
        except Exception:
            continue
        if not r:
            continue
        res["cmp"] = res["cmp"] or r.get("cmp", "")
        if not r.get("found"):
            continue
        res["found"] = True
        if len(r["text"]) > len(res["text"]):
            res["text"] = r["text"]
        res["buttons"] += [{"idx": b["idx"], "text": b["text"], "frame": i, "kind": kind_of(b["text"])} for b in r["buttons"]]
        res["pre"] += [p for p in r["pre"] if p and not NECESSARY_RE.search(p)]
    return res, frames


async def wait_banner(pg, tries=4, gap=700):
    """Consent tools often load late; look again a few times before deciding there is no banner."""
    banner, frames = await detect_banner(pg)
    for _ in range(tries):
        if banner["found"] and banner["buttons"]:
            break
        await asyncio.sleep(gap / 1000)
        banner, frames = await detect_banner(pg)
    return banner, frames


async def click_banner(pg, frames, banner, action):
    for fr in list(pg.frames):
        for sel in CMP_SEL[action]:
            try:
                loc = fr.locator(sel).first
                if await loc.count() and await loc.is_visible():
                    await loc.click(timeout=4000)
                    return sel
            except Exception:
                pass
    for b in banner["buttons"]:
        if b["kind"] == action:
            try:
                await frames[b["frame"]].locator('[data-pdpl-btn="' + str(b["idx"]) + '"]').first.click(timeout=4000)
                return b["text"]
            except Exception:
                pass
    return None


def check_tls(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as s0, ctx.wrap_socket(s0, server_hostname=host) as s:
            exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(s.getpeercert()["notAfter"]), tz=timezone.utc)
            out = {"valid": True, "version": s.version(), "expires": exp.date().isoformat(),
                   "days": (exp - datetime.now(timezone.utc)).days}
    except ssl.SSLCertVerificationError as ex:
        out = {"valid": False, "error": str(getattr(ex, "verify_message", ex))}
    except Exception as ex:
        out = {"valid": None, "error": type(ex).__name__}
    try:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        c.minimum_version, c.maximum_version = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
        c.set_ciphers("ALL:@SECLEVEL=0")
        with socket.create_connection((host, 443), timeout=6) as s0, c.wrap_socket(s0, server_hostname=host) as s:
            out["legacy"] = s.version()
    except Exception:
        out["legacy"] = None
    return out


def check_http(host):
    cur, path = host, "/"
    for _ in range(4):
        try:
            conn = http.client.HTTPConnection(cur, 80, timeout=8)
            conn.request("GET", path, headers={"User-Agent": UA})
            r = conn.getresponse()
            status, loc = r.status, r.getheader("Location") or ""
            conn.close()
        except Exception:
            return {"redirect": None}
        if status in (301, 302, 303, 307, 308) and loc:
            if loc.lower().startswith("https://"):
                return {"redirect": True, "location": loc}
            n = urlparse(urljoin("http://" + cur + path, loc))
            cur, path = n.hostname or cur, (n.path or "/") + ("?" + n.query if n.query else "")
            continue
        return {"redirect": False, "status": status}
    return {"redirect": False, "status": "redirect loop"}


def check_sectxt(base):
    try:
        req = urllib.request.Request(urljoin(base, "/.well-known/security.txt"), headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status == 200 and "contact:" in r.read(8192).decode("utf-8", "ignore").lower()
    except Exception:
        return False


def net_checks(host, base):
    """TLS, HTTP->HTTPS redirect and security.txt - plain sockets, run in a thread alongside the browser."""
    with ThreadPoolExecutor(max_workers=3) as ex:
        t, h, st = ex.submit(check_tls, host), ex.submit(check_http, host), ex.submit(check_sectxt, base)
        return {"tls": t.result(), "http": h.result(), "sectxt": st.result()}


def auto_parallel(setting=None):
    """Two browser sessions at once need roughly 1 GB; only do it when the container clearly has the memory."""
    v = str(setting if setting is not None else PARALLEL).strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    limit = None
    for f in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            raw = Path(f).read_text().strip()
            if raw.isdigit() and int(raw) < 1 << 46:
                limit = int(raw)
                break
        except Exception:
            pass
    if limit is None:
        try:
            limit = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        except Exception:
            return False
    return limit >= 1.5 * (1 << 30)


def is_lib(url, rtype):
    """A plain code download (gtag.js, fbevents.js, a stylesheet): script type, no hit parameters, and either a
    .js/.css path or only loader parameters such as id= / v=. Script-type beacons (e.g. X Pixel adsct) are hits."""
    if rtype not in LIB_TYPES or TRACK_PARAM_RE.search(url):
        return False
    u = urlparse(url)
    return bool(LIB_EXT_RE.search(u.path or "") or LIB_PATH_RE.search(u.path or "")) or \
        set(parse_qs(u.query, keep_blank_values=True)) <= LOADER_KEYS


def vendors(reqs, site, phases):
    """Group third-party requests by vendor. mode: 'tracking' = data-sending calls not marked as consent-denied;
    'denied' = only Google Consent Mode calls with ad and analytics storage denied (gcs=G100);
    'script' = the vendor's code was downloaded but it made no calls."""
    out = {}
    for item in reqs or []:
        url, ph, rtype = (item + ("other",))[:3] if len(item) == 2 else item
        h = host_of(url)
        if ph not in phases or not url.startswith("http") or not h:
            continue
        if site_of(h) == site:
            pu = urlparse(url)
            if SGTM_HIT_RE.search(pu.path or "") and re.search(r"(^|&)(tid|en|v)=", pu.query or ""):
                name, cat, cc = "Google Analytics via the site's own server", "analytics", "??"
            elif SGTM_LOADER_RE.search(pu.path or "") and re.search(r"(^|&)id=(GTM|G|AW|DC)-", pu.query or "", re.I):
                name, cat, cc = "Google tag loader via the site's own server", "tag_manager", "??"
            else:
                continue
        else:
            name, cat, cc = classify(url) or (site_of(h), "unclassified", "??")
        v = out.setdefault(name, {"vendor": name, "cat": cat, "cc": cc, "domains": set(), "hits": 0, "denied": 0, "libs": 0,
                                  "samples": []})
        v["domains"].add(h)
        if is_lib(url, rtype):
            v["libs"] += 1
            continue
        v["hits"] += 1
        if parse_qs(urlparse(url).query).get("gcs", [""])[0][2:4] == "00":   # Google Consent Mode 'denied' = G100
            v["denied"] += 1
        elif len(v["samples"]) < 2:
            v["samples"].append(url)
    for v in out.values():
        v["mode"] = "tracking" if v["hits"] > v["denied"] else "denied" if v["hits"] else "script"
    return out


def vd(v):
    return v["vendor"] + " (" + v["cat"] + ", HQ " + v["cc"] + ")"


def short_url(url):
    """host/path plus the few parameters that show what the call was (event name, consent state, account id)."""
    u = urlparse(url)
    q = parse_qs(u.query)
    keep = [k + "=" + q[k][0][:24] for k in ("ev", "en", "event", "gcs", "tid", "id") if k in q][:3]
    out = (u.hostname or "") + (u.path or "/")[:60] + ("?" + "&".join(keep) if keep else "")
    return out[:110]


def vds(v):
    """Vendor description plus an example of the call that was seen."""
    return vd(v) + (" - e.g. " + short_url(v["samples"][0]) if v.get("samples") else "")


def track_cookies(cookies):
    out, seen = [], set()
    for c in cookies or []:
        for r, vendor in TRACK_COOKIES:
            if r.search(c["name"]) and c["name"] not in seen:
                seen.add(c["name"])
                out.append({"name": c["name"], "vendor": vendor})
                break
    return out


def cookie_changes(before, after):
    """Split tracking cookies seen after 'Reject' into ones written after the choice (new, changed value or
    refreshed expiry) and ones simply left over from before the choice."""
    prev = {(c["name"], c.get("domain", "")): c for c in before or []}
    active, left = [], []
    for c in after or []:
        if not any(r.search(c["name"]) for r, _ in TRACK_COOKIES):
            continue
        p = prev.get((c["name"], c.get("domain", "")))
        why = "new" if p is None else "new value" if p.get("value") != c.get("value") else \
            "expiry extended" if (c.get("expires", -1) or -1) - (p.get("expires", -1) or -1) > 1 else ""
        if why:
            active.append(dict(track_cookies([c])[0], why=why))
        else:
            left.extend(track_cookies([c]))
    return active, left


def locale_prefix(final, links, site):
    """'/en-AE' when the site keeps its pages under a language/region folder."""
    seg = (urlparse(final).path or "/").strip("/").split("/")[0]
    if LOCALE_SEG_RE.match(seg or ""):
        return "/" + seg
    count, total = {}, 0
    for l in links:
        u = urlparse(l["href"])
        if site_of(u.hostname or "") != site:
            continue
        total += 1
        first = (u.path or "/").strip("/").split("/")[0]
        if LOCALE_SEG_RE.match(first or ""):
            count[first] = count.get(first, 0) + 1
    if count and total:
        seg, n = max(count.items(), key=lambda kv: kv[1])
        if n / total >= 0.4:
            return "/" + seg
    return ""


def arabic_ratio(text):
    letters = re.findall(r"[^\W\d_]", text or "")
    return sum("\u0600" <= ch <= "\u06ff" for ch in letters) / len(letters) if letters else 0.0


def arabic_evidence(pol, home):
    if pol.get("ar_url"):
        return "Arabic notice: " + pol["ar_url"]
    if arabic_ratio(pol.get("main") or pol.get("text", "")) > 0.3:
        return "Privacy notice text is in Arabic"
    if (home.get("lang") or "").lower().startswith("ar"):
        return "Site is served in Arabic"
    for a in (pol.get("alts") or []) + (home.get("alts") or []):
        if (a.get("lang") or "").lower().startswith("ar"):
            return "Arabic version: " + a["href"]
    for l in (pol.get("links") or []) + (home.get("links") or []):
        if re.fullmatch(r"\s*(العربية|عربي|ar|arabic)\s*", l["text"], re.I) or re.search(r"/ar(/|-|$)|[?&](lang|locale)=ar\b", l["href"], re.I):
            return "Arabic language link: " + l["href"]
    for t in (pol.get("langs") or []) + (home.get("langs") or []):
        return "Arabic language switch on the site (\"" + t + "\")"
    return ""


def arabic_urls(url):
    """Likely Arabic twin of a notice address: /en-AE/x -> /ar-AE/x, /en/x -> /ar/x, ?lang=en -> ?lang=ar."""
    out = []
    u = urlparse(url)
    p2 = re.sub(r"^/en([-_][A-Za-z]{2})?(?=/|$)", lambda m: "/ar" + (m.group(1) or ""), u.path or "", flags=re.I)
    if p2 != u.path:
        out.append(u._replace(path=p2).geturl())
    q2 = re.sub(r"(^|&)(lang|locale|language)=en\b", r"\1\2=ar", u.query or "", flags=re.I)
    if q2 != u.query:
        out.append(u._replace(query=q2).geturl())
    return out


def notice_kind(info):
    """'full' for a real notice, 'brief' for a short one, '' for anything else (including hub pages)."""
    mt = info.get("main") or info.get("text", "")
    words, kw = len(mt.split()), len(POLICY_KW.findall(mt))
    subst = sum(1 for r in SUBSTANCE if r.search(mt))
    if words >= 150 and kw >= 3 and subst >= 3:
        return "full"
    if words >= 40 and kw >= 1 and subst >= 2:
        return "brief"
    return ""


def notice_links(info, tried):
    """Links on a page that lead to (more) privacy notices - used to follow hub pages."""
    found = []
    for pool in (info.get("mlinks") or [], info.get("links") or []):
        for k in rank_links(pool):
            if k.rstrip("/") not in tried and k not in found:
                found.append(k)
        if found:
            break
    return found[:4]


def merge_notices(pages):
    first = pages[0]
    return dict(first, found=True, url=first["url"], urls=[p["url"] for p in pages],
                main="\n".join(p.get("main") or p.get("text", "") for p in pages),
                text="\n".join(p.get("text", "") for p in pages),
                links=[l for p in pages for l in p.get("links", [])], mlinks=[l for p in pages for l in p.get("mlinks", [])],
                langs=[t for p in pages for t in p.get("langs", [])],
                alts=[a for p in pages for a in p.get("alts", [])])


def form_info(f):
    fl = f["fields"]
    types = [x["type"] for x in fl]
    blobs = [" ".join([x["name"], x["id"], x["ph"], x["ac"], x["aria"], x["label"]]).lower() for x in fl]
    if len(fl) <= 2 and "email" not in types and ("search" in types or any(re.search(r"\b(q|s|search|query)\b|بحث", b) for b in blobs)):
        return None                                                    # site search box
    if "password" in types and len([t for t in types if t not in ("checkbox", "password")]) <= 1:
        return None                                                    # login form
    c = {"pii": set(), "sens": set(), "ids": False, "prechecked": []}
    for x, b in zip(fl, blobs):
        t = x["type"]
        if t == "checkbox":
            if x["checked"] and re.search(r"agree|consent|newsletter|marketing|offers|promotion|subscribe|أوافق|موافق|النشرة|العروض", b):
                c["prechecked"].append(x["label"] or x["name"] or "unlabelled box")
            continue
        if t == "file":
            if re.search(r"passport|emirates|identity|جواز|الهوية", b):
                c["pii"].add("id_document")
                c["ids"] = True
            continue
        if t in ("email", "tel"):
            c["pii"].add("email" if t == "email" else "phone")
        else:
            for k, r in PII.items():
                if r.search(b) and not (k == "address" and re.search(r"e-?mail|ip.?address|web", b)):
                    c["pii"].add(k)
                    break
        c["sens"].update(k for k, r in SENS.items() if r.search(b))
    c["ids"] = c["ids"] or bool(c["pii"] & {"emirates_id", "passport"})
    hay = " ".join([f.get("text", ""), f.get("ctx", "")] + [l["text"] + " " + l["href"] for l in f.get("links", [])])
    c["notice"] = bool(PRIVACY_RE.search(hay))
    c["plink"] = bool(f.get("plink"))                                  # page has a privacy link somewhere (e.g. footer)
    c["insecure"] = f.get("action", "").startswith("http://") or not f["page"].startswith("https://")
    c["pii"], c["sens"] = sorted(c["pii"]), sorted(c["sens"])
    return c


def rank_links(links):
    sc = {}
    for l in links:
        t, h = l["text"].lower(), l["href"].lower()
        if not h.startswith("http"):
            continue
        s = 5 if re.search(r"privacy (policy|notice|statement)|سياسة الخصوصية|إشعار الخصوصية", t) else \
            3 if re.search(r"privacy|الخصوصية|حماية البيانات", t) else 0
        s += 2 if re.search(r"privacy|data-protection", h) else 0
        s -= 2 if ("cookie" in t + h and s < 5) else 0
        if s > 0:
            k = l["href"].split("#")[0]
            sc[k] = max(sc.get(k, 0), s)
    return sorted(sc, key=lambda k: -sc[k])


# ------------------------------------------------------------------ scanner
class Scan:
    def __init__(self, client, o):
        u = client["url"].strip()
        self.url = u if re.match(r"https?://", u, re.I) else "https://" + u
        self.client, self.o, self.d, self.res, self.na = client, o, {}, [], []
        self.ptext, self.pbody, self.law_note = "", [], ""
        self.site = site_of(host_of(self.url))
        self.unassessed = {}                                   # category -> reason it could not be scored
        self.hidden_tags = []
        self.parallel = auto_parallel(getattr(o, "parallel", None))
        self.timings = {}

    def add(self, fid, cat, sev, title, basis, ref, ev, fix=""):
        self.res.append(F(fid, cat, sev, title, basis, ref, ev, fix))

    def ok(self, fid, cat, title, basis, ref, ev):
        self.res.append(F(fid, cat, "info", title, basis, ref, ev, "", True))

    def _min_wait(self):
        return int(getattr(self.o, "settle", 3000) or 3000)

    # -------------------------------------------------------------- collection (browser)
    async def _ctx(self, b):
        ctx = await b.new_context(user_agent=UA, locale="en-AE", timezone_id="Asia/Dubai",
                                  viewport={"width": 1366, "height": 900}, ignore_https_errors=True)
        await ctx.add_init_script(FP_JS)

        async def _abort(route):
            try:
                await route.abort()
            except Exception:
                pass
        await ctx.route(MEDIA_RE, _abort)
        net = {"reqs": [], "phase": "pre", "last3p": time.monotonic(), "abort": _abort}

        def on_request(r):
            try:
                url, rtype = r.url, r.resource_type
            except Exception:
                return
            net["reqs"].append((url, net["phase"], rtype))
            if site_of(host_of(url)) != self.site:
                net["last3p"] = time.monotonic()
        ctx.on("request", on_request)
        return ctx, net

    async def _reload(self, pg, net):
        try:
            await pg.reload(wait_until="domcontentloaded", timeout=self.o.timeout)
        except Exception:
            pass
        await settle_net(pg, net, 1500)
        await interact(pg, net, self._min_wait())

    def collect(self):
        t0 = time.monotonic()
        self._net_ex = ThreadPoolExecutor(max_workers=2)
        self._net_futs = {host_of(self.url): self._net_ex.submit(net_checks, host_of(self.url), self.url)}  # runs alongside the browser
        try:
            asyncio.run(self._collect_async())
        except BaseException:
            self._net_ex.shutdown(wait=False, cancel_futures=True)    # do not hold the error back for the socket checks
            raise
        d = self.d
        h = host_of(d["final"])
        fut = self._net_futs.get(h) or self._net_ex.submit(net_checks, h, d["final"])
        checks = fut.result()
        self._net_ex.shutdown(wait=False, cancel_futures=True)
        d["tls"], d["http"], d["sectxt"] = checks["tls"], checks["http"], checks["sectxt"]
        self.timings["collect"] = round(time.monotonic() - t0, 1)

    async def _collect_async(self):
        o, d = self.o, self.d
        launch = {"headless": not o.headful, "args": CHROME_ARGS}
        if o.proxy:
            p = urlparse(o.proxy)
            launch["proxy"] = {"server": p.scheme + "://" + str(p.hostname) + (":" + str(p.port) if p.port else "")}
            if p.username:
                launch["proxy"].update(username=p.username, password=p.password or "")
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda lp, c: None if "TargetClosed" in repr(c.get("exception")) else lp.default_exception_handler(c))
        async with async_playwright() as pw:
            b = await pw.chromium.launch(**launch)
            try:
                if self.parallel and not o.no_reject:
                    ra, rb = await asyncio.gather(self._limited(self._session_a(b), "a"), self._limited(self._session_b(b), "b"),
                                                  return_exceptions=True)
                    if isinstance(ra, BaseException):
                        raise ra
                    if not d["banner"]["found"]:                   # session B clicked nothing: discard it
                        d["rejected"] = None
                else:
                    await self._limited(self._session_a(b), "a")
                    if d["banner"]["found"] and not o.no_reject:
                        try:
                            await self._limited(self._session_b(b), "b")
                        except Exception:
                            d["rejected"] = None
            finally:
                await b.close()

    async def _limited(self, coro, which):
        """Hard time limit per browser session, so one hung page cannot block the scan queue."""
        try:
            return await asyncio.wait_for(coro, SESSION_LIMIT)
        except asyncio.TimeoutError:
            if which == "a":
                raise RuntimeError("The website took too long to respond (over " + str(SESSION_LIMIT) + " seconds), so no "
                                   "report was made. Try again later.")
            self.d["rejected"] = None
            self.na.append("What happens after 'Reject' (the second browser session timed out)")

    async def _session_a(self, b):                   # clean visit -> Accept -> reload -> notice + form pages
        o, d = self.o, self.d
        t0 = time.monotonic()
        ctx, net = await self._ctx(b)
        pg = await ctx.new_page()
        last_doc = {}

        def on_response(r):
            try:
                if r.request.is_navigation_request() and r.frame == pg.main_frame:
                    last_doc["resp"] = r
            except Exception:
                pass
        pg.on("response", on_response)
        try:
            resp = await pg.goto(self.url, wait_until="domcontentloaded", timeout=o.timeout)
        except Exception as ex:
            await ctx.close()
            raise RuntimeError("Could not open " + self.url + " (" + str(ex).splitlines()[0] + ")")
        self.site = site_of(host_of(pg.url))
        fh = host_of(pg.url)
        if fh not in self._net_futs:                     # redirected (e.g. to www.): start that host's checks now
            self._net_futs[fh] = self._net_ex.submit(net_checks, fh, pg.url)
        await settle_net(pg, net, 1500)
        st = resp.status if (resp and pg.url.split("#")[0] == resp.url.split("#")[0]) else 200   # a JS redirect moved on
        title = await jseval(pg, "() => document.title || ''") or ""
        words = len((await jseval(pg, "() => document.body ? document.body.innerText : ''") or "").split())
        if (st in (401, 403, 429, 503) and (BLOCKED_RE.search(title) or words < 150)) or (BLOCKED_RE.search(title) and words < 150):
            await ctx.close()
            raise RuntimeError("The website blocked the automated browser (HTTP " + str(st) + ", bot-protection page), so no "
                               "report was made. Try again later, or set SCAN_PROXY to a UAE proxy.")
        final_resp = last_doc.get("resp") or resp                # the page as it is now, after any JavaScript redirect
        d["final"], d["status"] = pg.url, (final_resp.status if final_resp else None)
        self.site = site_of(host_of(pg.url))
        try:
            d["headers"] = {k.lower(): v for k, v in (await final_resp.all_headers()).items()} if final_resp else {}
        except Exception:
            d["headers"] = {}
        banner0, _ = await wait_banner(pg)
        await interact(pg, net, self._min_wait())           # loads tags that wait for the first scroll / mouse move
        d["home"] = await jseval(pg, PAGE_JS) or EMPTY       # read after scrolling, so lazy footers and links are included
        banner, frames = await detect_banner(pg)
        if banner0["found"] and not banner["found"]:
            d["banner_scrolled_away"] = True                 # the banner closed itself when the visitor scrolled
            banner = banner0
        mp = bool(await jseval(pg, PLINK_JS))
        d["forms"] = [dict(f, page=pg.url, plink=f.get("plink") or mp) for f in await frames_eval(pg, FORMS_JS)]
        d["fp"] = await frames_eval(pg, "() => window.__fp || []")
        d["banner"], d["ck_pre"], d["accepted"] = banner, await ctx.cookies(), None
        if banner["found"]:
            i0 = len(net["reqs"])
            net["phase"] = "accept"                          # anything the click itself triggers belongs to 'Accept'
            d["accepted"] = await click_banner(pg, frames, banner, "accept")
            if d["accepted"]:
                await asyncio.sleep(1.5)
                net["phase"] = "post"
                await self._reload(pg, net)
                d["ck_acc"], d["withdraw"] = await ctx.cookies(), await jseval(pg, WITHDRAW_JS)
                if not d["withdraw"]:                        # look for a settings button on the cookie policy page
                    cps = [l["href"] for l in d["home"]["links"] if re.search(r"cookie", l["text"] + " " + l["href"], re.I)
                           and site_of(host_of(l["href"])) == self.site]
                    if cps:
                        try:
                            await pg.goto(cps[0], wait_until="domcontentloaded", timeout=min(o.timeout, 20000))
                            await settle_dom(pg)
                            found = await jseval(pg, WITHDRAW_BTN_JS) or await jseval(pg, WIDGET_JS)
                            if found:
                                d["withdraw"], d["withdraw_where"] = found, cps[0]
                        except Exception:
                            pass
            else:                                            # nothing was clicked: those requests are still pre-consent
                net["reqs"][i0:] = [(u, "pre", t) for u, _, t in net["reqs"][i0:]]
                net["phase"] = "pre"
        self.timings["consent_a"] = round(time.monotonic() - t0, 1)
        await pg.close()                                     # free memory before opening the text-only pages
        net["phase"] = "crawl"
        await ctx.route(IMG_RE, net["abort"])                # notice and form pages: no images needed
        t1 = time.monotonic()
        if self.parallel:
            d["policy"], d["form_pages"] = await asyncio.gather(self._find_policy(ctx), self._crawl(ctx))
        else:
            d["policy"] = await self._find_policy(ctx)
            d["form_pages"] = await self._crawl(ctx)
        self.timings["pages"] = round(time.monotonic() - t1, 1)
        d["reqs_a"] = net["reqs"]
        await ctx.close()

    async def _session_b(self, b):                   # fresh visit -> Reject -> reload
        d = self.d
        d["rejected"] = None
        t0 = time.monotonic()
        ctx, net = await self._ctx(b)
        try:
            pg = await ctx.new_page()
            await pg.goto(self.url, wait_until="domcontentloaded", timeout=self.o.timeout)
            await settle_net(pg, net, 1500)
            await wait_banner(pg)
            await interact(pg, net, self._min_wait())
            banner, frames = await detect_banner(pg)
            if banner["found"]:
                net["phase"] = "reject"
                d["rejected"] = await click_banner(pg, frames, banner, "reject")
            if d["rejected"]:
                await asyncio.sleep(1.5)
                d["ck_rej_before"] = await ctx.cookies()     # compare against the state just before the reload
                net["phase"] = "post"
                await self._reload(pg, net)
                d["ck_rej"], d["reqs_b"] = await ctx.cookies(), net["reqs"]
        except Exception:
            d["rejected"] = None
        finally:
            await ctx.close()
            self.timings["consent_b"] = round(time.monotonic() - t0, 1)

    async def _pdf_text(self, ctx, url):
        """Privacy notices published as PDF files: download and extract the text."""
        try:
            r = await ctx.request.get(url, timeout=20000)
            body = await r.body()
            if not r.ok or b"%PDF" not in body[:1024]:
                return None, "unreadable (PDF link did not return a PDF)"
            import io
            from pypdf import PdfReader
            raw = "\n".join((pg_.extract_text() or "") for pg_ in PdfReader(io.BytesIO(body)).pages[:40])
            text = "\n".join(re.split(r"(?<=[.!?])\s+", re.sub(r"\s*\n\s*", " ", raw)))   # one sentence per line
            if len(text.split()) < 50:
                return None, "unreadable (privacy notice is a PDF without a text layer, e.g. a scan)"
            return {"url": url, "title": "", "lang": "", "main": text, "text": text, "links": [], "mlinks": [], "alts": [],
                    "langs": [], "html": "", "pdf": True}, ""
        except ImportError:
            return None, "unreadable (privacy notice is a PDF and pypdf is not installed)"
        except Exception:
            return None, "unreadable (privacy notice is a PDF that could not be read)"

    async def _open_text_page(self, pg, url):
        """Load a page for its text only. Returns (info, status-note)."""
        if urlparse(url).path.lower().endswith(".pdf"):
            return await self._pdf_text(pg.context, url)
        try:
            r = await pg.goto(url, wait_until="domcontentloaded", timeout=min(self.o.timeout, 20000))
        except Exception as ex:
            if "download" in str(ex).lower():
                return await self._pdf_text(pg.context, url)
            return None, "could not load (" + (str(ex).splitlines() or ["error"])[0][:60] + ")"
        status = r.status if r else 0
        if status in (401, 403, 429) or status >= 500:
            return None, "blocked (HTTP " + str(status) + ")"
        if status >= 400:
            return None, "HTTP " + str(status)
        await settle_dom(pg)
        info = await jseval(pg, PAGE_JS) or EMPTY
        if len((info.get("main") or "").split()) < 150:          # text may still be loading (embedded notice tools)
            await settle_dom(pg, 1200, 3000)
            info = await jseval(pg, PAGE_JS) or info
        if BLOCKED_RE.search(info.get("title", "")) and len((info.get("main") or "").split()) < 150:
            return None, "blocked (bot check page)"
        return dict(info, url=pg.url), ""

    async def _find_policy(self, ctx):
        """Follow the homepage privacy link(s); when the page is a hub ('select your notice'), read the notices it
        links to. Fall back to common addresses, including the site's language folder (e.g. /en-AE/privacy)."""
        d = self.d
        linked = rank_links(d["home"]["links"])
        prefix = locale_prefix(d["final"], d["home"]["links"], self.site)
        probes = [urljoin(d["final"], prefix + p) for p in ("/privacy-policy", "/privacy", "/privacy-notice")] if prefix else []
        probes += [urljoin(d["final"], p) for p in PROBE]
        queue = [(u, "link") for u in linked[:4]] + [(u, "probe") for u in probes]
        tried, loads, full, brief, notes, pg = set(), 0, [], None, [], await ctx.new_page()
        try:
            while queue and loads < 10:
                url, how = queue.pop(0)
                if full and not how.startswith("hub"):
                    break                                    # a notice was found; skip the remaining guesses
                if url.rstrip("/") in tried:
                    continue
                tried.add(url.rstrip("/"))
                loads += 1
                info, note = await self._open_text_page(pg, url)
                if info is None:
                    if how != "probe":
                        notes.append((how, url + ": " + note))
                    continue
                tried.add(info["url"].rstrip("/"))
                kind = notice_kind(info)
                if kind == "full":
                    full.append(dict(info, how=how))
                    if not how.startswith("hub") or len(full) >= 3:
                        break
                    continue
                if kind == "brief" and how in ("link", "hub-link") and brief is None:
                    brief = dict(info, how=how)
                subs = notice_links(info, tried) if how in ("link", "probe") else []
                if subs:                                     # hub page: read the notices it lists
                    queue = [(u, "hub-" + how) for u in subs] + [q for q in queue if not q[1].startswith("hub")]
            pages = full or ([brief] if brief else [])
            if pages:
                res = merge_notices(pages)
                res["linked"] = any(p["how"] in ("link", "hub-link") for p in pages)
                res["kind"] = "full" if full else "brief"
                if not arabic_evidence(res, d["home"]):           # look for an Arabic twin such as /ar-AE/...
                    for au in [a for p in pages for a in arabic_urls(p["url"])][:2]:
                        info, _ = await self._open_text_page(pg, au)
                        if info and arabic_ratio(info.get("main") or info.get("text", "")) > 0.3:
                            res["ar_url"] = info["url"]
                            break
                return res
        finally:
            await pg.close()
        return {"found": False, "linked": bool(linked), "tried": sorted(tried)[:8],
                "blocked": [n for h, n in notes if h in ("link", "hub-link") and ("blocked" in n or "unreadable" in n)],
                "notes": [n for _, n in notes]}

    async def _crawl(self, ctx):
        d, todo = self.d, []
        home = d["final"].split("#")[0].rstrip("/")
        for l in d["home"]["links"]:
            u = l["href"].split("#")[0]
            if (u.startswith("http") and site_of(host_of(u)) == self.site and u.rstrip("/") != home and u not in todo
                    and (FORMPAGE_RE.search(l["text"]) or FORMPAGE_RE.search(urlparse(u).path))):
                todo.append(u)
        todo = todo[: self.o.max_pages]
        pg = await ctx.new_page()
        try:
            for u in todo:
                try:
                    await pg.goto(u, wait_until="domcontentloaded", timeout=min(self.o.timeout, 20000))
                    await settle_dom(pg, 900, 5000)
                    found = await frames_eval(pg, FORMS_JS)
                    pii_found = any((fi_ := form_info(dict(f, page=pg.url))) and (fi_["pii"] or fi_["sens"]) for f in found)
                    if not pii_found:                        # forms lower down the page may load only when scrolled to
                        await jseval(pg, "() => window.scrollTo(0, document.body ? document.body.scrollHeight : 0)")
                        await settle_dom(pg, 600, 2500)
                        found = await frames_eval(pg, FORMS_JS)
                    mp = bool(await jseval(pg, PLINK_JS))
                    d["forms"] += [dict(f, page=pg.url, plink=f.get("plink") or mp) for f in found]
                except Exception:
                    pass
        finally:
            await pg.close()
        return todo

    # -------------------------------------------------------------- analysis
    def analyse(self):
        d, s = self.d, self.site
        ra = d.get("reqs_a", [])
        d["v_pre"], d["v_acc"] = vendors(ra, s, {"pre"}), vendors(ra, s, {"accept", "post"})
        d["v_all"] = vendors(ra, s, {"pre", "accept", "post", "crawl"})
        d["v_rej"] = vendors(d.get("reqs_b"), s, {"reject", "post"}) if d.get("rejected") else None
        if (d.get("status") or 0) >= 400:
            self.na.append("Homepage returned HTTP " + str(d["status"]) + "; results may reflect a block or error page")
        # Tags set up in the code that never loaded in any session: the site hides them from automated browsers
        seen = set(d["v_all"]) | set(d.get("v_rej") or {})
        all_urls = " ".join(u for u, *_ in list(ra) + list(d.get("reqs_b") or []))
        b = d.get("banner") or {}
        hidden = []
        if not (b.get("found") and not d.get("accepted")):
            for lab, ev, names in tags_in_code(d["home"].get("html", "")):
                tag_id = re.search(r"\b(?:GTM|G|AW|DC)-[A-Z0-9]+", ev)
                if any(n in seen for n in names) or (tag_id and tag_id.group(0) in all_urls):
                    continue                                   # it did load (a custom first-party loader still carries the ID)
                hidden.append((lab, ev))
        self.hidden_tags = hidden
        if hidden:
            ids = ", ".join(lab + " (" + ev + ")" for lab, ev in hidden[:6])
            self.add("C-HIDDEN", "advisory", "info", "Tracking is set up on this site but did not load for the automated scanner: check manually",
                     "advisory", "PDPL Art. 4; Art. 6", "Found in the page code but never requested: " + ids + ". Some sites skip their "
                     "tags when they detect an automated browser, so the consent results may be incomplete.",
                     "Open the site in a normal browser with developer tools (Network tab), scroll the page, and check which "
                     "trackers load before any consent choice and after 'Reject'.")
        self._consent()
        if hidden:
            real = any(f.cat == "consent" and not f.passed and f.sev in ("critical", "high", "medium", "low") for f in self.res)
            if not real:                                       # nothing observed: the clean result is not trustworthy, do not score it
                self.unassessed["consent"] = "tracking is set up but did not load for an automated browser"
                self.na.append("Consent and tracking behaviour (tracking tags are set up but did not load for the automated browser)")
            else:                                              # real gaps were observed: keep them scored, flag that more may exist
                self.na.append("Tags that did not load for the automated browser: " + ", ".join(lab for lab, _ in hidden[:4]))
        self._fingerprint()
        fi = self._forms()
        self._notice(fi)
        self._transfers()
        self._security()
        self._advisories(fi)

    def _consent(self):
        d, b = self.d, self.d["banner"]
        REF = "PDPL Art. 4 (no processing without consent unless an Art. 4 exception applies); Art. 1 (online identifiers are personal data)"
        VALID = "PDPL Art. 1 (consent must be clear and unambiguous, by a positive statement or action); Art. 6(1)(b)"
        ne = [v for v in d["v_pre"].values() if v["cat"] in NON_ESSENTIAL]
        hard = [v for v in ne if v["mode"] == "tracking"]
        soft = [v for v in ne if v["mode"] == "denied"]
        ck = track_cookies(d.get("ck_pre"))
        ck_vendors = {c["vendor"].split()[0].lower() for c in ck}
        lib = [v for v in ne if v["mode"] == "script" and v["vendor"].split()[0].lower() not in ck_vendors]
        if hard or ck:
            ev = []
            if hard:
                ev.append("Tracking calls before consent: " + "; ".join(vds(v) for v in hard))
            if ck:
                ev.append("Tracking cookies before consent: " + ", ".join(c["name"] + " (" + c["vendor"] + ")" for c in ck[:12]))
            if soft:
                ev.append("Consent Mode 'denied' pings: " + "; ".join(vd(v) for v in soft))
            if lib:
                ev.append("Scripts downloaded without tracking calls: " + "; ".join(vd(v) for v in lib))
            self.add("C-PRECONSENT", "consent", "critical", "Trackers load before the visitor consents", "law", REF, " | ".join(ev),
                     "Block analytics, advertising, visitor-identification and session-replay tags until the visitor opts in "
                     "(fire them in Google Tag Manager only on a consent-granted trigger) and remove tags hard-coded in templates.")
        elif soft:
            self.add("C-PRECONSENT", "consent", "medium", "Google tags send cookieless pings before consent", "law", REF,
                     "Consent Mode 'denied' pings to: " + "; ".join(vd(v) for v in soft) +
                     (" | Scripts downloaded without tracking calls: " + "; ".join(vd(v) for v in lib) if lib else ""),
                     "These pings still send IP address and device data. The PDPL has no legitimate-interests ground, "
                     "so consider Consent Mode 'basic' (nothing loads until consent).")
        elif lib:
            self.add("C-PRECONSENT", "consent", "low", "Tracking scripts are downloaded before consent (no tracking calls seen)",
                     "law", REF, "Scripts only: " + "; ".join(vd(v) for v in lib),
                     "No tracking calls or cookies were seen, but each download still sends the visitor's IP address to the "
                     "vendor. Load these scripts only after consent.")
        else:
            if not self.hidden_tags:
                self.ok("C-PRECONSENT", "consent", "No analytics or advertising tracking before consent", "law", REF,
                    "No known non-essential third-party requests or tracking cookies before interaction.")
        unk = sorted({h for v in d["v_pre"].values() if v["cat"] == "unclassified" and v["mode"] == "tracking" for h in v["domains"]})
        if unk:
            self.add("C-UNKNOWN", "consent", "low", "Unidentified third parties make calls before consent - review", "law", REF,
                     ", ".join(unk[:10]), "Identify each service. If it tracks visitors (analytics, advertising, visitor "
                     "identification), load it only after consent.")
        anytrack = bool(ck) or any(v["cat"] in NON_ESSENTIAL for v in d["v_all"].values())
        if not b["found"]:
            note = (" A consent tool (" + b["cmp"] + ") is installed but showed no banner; it may only appear in some "
                    "regions - re-scan with a UAE --proxy.") if b["cmp"] else ""
            if anytrack:
                self.add("C-BANNER", "consent", "high", "No consent banner although tracking is present", "law",
                         "PDPL Art. 4; Art. 6(1)(a)-(c)", "No cookie/consent banner appeared on the first visit." + note,
                         "Add a consent tool with Accept, Reject and Settings on the first screen, in English and "
                         "Arabic, and keep consent records (Art. 6(1)(a)).")
            else:
                if not self.hidden_tags:
                    self.ok("C-BANNER", "consent", "No banner needed for what was observed", "law", "PDPL Art. 4",
                            "No banner and no non-essential trackers." + note)
            return
        kinds = {x["kind"] for x in b["buttons"]}
        btns = ", ".join('"' + x["text"] + '"' for x in b["buttons"][:8]) or "none found"
        self.ok("C-BANNER", "consent", "Consent banner present" + (" (" + b["cmp"] + ")" if b["cmp"] else ""), "law",
                "PDPL Art. 6(1)(b)", "Buttons: " + btns)
        if "reject" in kinds:
            self.ok("C-REJECT", "consent", "'Reject' offered on the first screen", "law", VALID, "Buttons: " + btns)
        elif kinds & {"settings", "save"}:
            self.add("C-REJECT", "consent", "medium", "No 'Reject' button on the first screen", "law", VALID,
                     "Buttons: " + btns, "Add 'Reject all' with the same prominence as 'Accept all'.")
        else:
            self.add("C-REJECT", "consent", "high", "Banner gives no way to refuse", "law", VALID, "Buttons: " + btns,
                     "Add 'Reject all' next to 'Accept all'; an accept-only banner is not a real choice.")
        if d.get("banner_scrolled_away"):
            self.add("C-SCROLL", "consent", "high", "Banner closes itself when the visitor scrolls", "law", VALID,
                     "The consent banner was visible on arrival and disappeared after the page was scrolled, without any "
                     "button being clicked.", "Keep the banner until the visitor makes a choice; scrolling is not consent.")
        m = IMPLIED_RE.search(b["text"])
        if m:
            self.add("C-IMPLIED", "consent", "high", "Banner relies on implied consent (continued browsing)", "law", VALID,
                     snip(b["text"], m), "Remove 'by continuing you agree' wording; consent must be a positive action.")
        if b["pre"]:
            self.add("C-PRECHECK", "consent", "high", "Consent toggles switched on by default", "law", VALID,
                     "On by default: " + "; ".join(b["pre"][:6]), "Default every non-essential purpose to off.")
        W = "PDPL Art. 6(1)(c), 6(2)"
        if d.get("accepted"):
            if d.get("withdraw"):
                self.ok("C-WITHDRAW", "consent", "Permanent link to change or withdraw consent", "law", W, "Found: " + str(d["withdraw"]) +
                        (" (on the cookie policy page " + d["withdraw_where"] + ", not on the homepage)" if d.get("withdraw_where") else ""))
            else:
                self.add("C-WITHDRAW", "consent", "medium", "No visible way to withdraw consent after accepting", "law", W,
                         "After accepting, no 'Cookie settings' link or consent widget was found.",
                         "Add a permanent 'Cookie settings' link in the footer that reopens the consent choices.")
            new = [v for k, v in d["v_acc"].items() if v["cat"] in NON_ESSENTIAL and v["mode"] == "tracking"
                   and (k not in d["v_pre"] or d["v_pre"][k]["mode"] != "tracking")]
            if new:
                self.add("C-ACCEPTED", "advisory", "info", "Trackers switched on by 'Accept'", "advisory",
                         "PDPL Art. 13(1)(b), (d)", "; ".join(vd(v) for v in new),
                         "Make sure each vendor listed here is named, with its purpose, in the cookie/privacy notice.")
        else:
            self.na.append("Consent withdrawal link (the scanner could not click 'Accept' automatically)")
        RR = "PDPL Art. 4; Art. 6(2)"
        if d.get("rejected"):
            rne = [v for v in (d["v_rej"] or {}).values() if v["cat"] in NON_ESSENTIAL]
            rhard = [v for v in rne if v["mode"] == "tracking"]
            rsoft = [v for v in rne if v["mode"] == "denied"]
            rlib = [v for v in rne if v["mode"] == "script"]
            rck, rleft = cookie_changes(d.get("ck_rej_before"), d.get("ck_rej"))
            libv = {v["vendor"].split()[0].lower() for v in rlib}                 # vendor code still downloaded, no calls
            cdesc = lambda cs: ", ".join(c["name"] + " (" + c["vendor"] + ", " + c["why"] + ")" for c in cs[:12])
            if rhard:
                ev = ["Tracking calls after 'Reject': " + "; ".join(vds(v) for v in rhard)]
                if rck:
                    ev.append("Tracking cookies written after 'Reject': " + cdesc(rck))
                if rleft:
                    ev.append("Cookies from before the choice left in place: " + ", ".join(c["name"] + " (" + c["vendor"] + ")" for c in rleft[:12]))
                self.add("C-REJECTED", "consent", "critical", "Tracking continues after the visitor clicks 'Reject'", "law", RR,
                         " | ".join(ev), "Make the consent tool block tags on rejection and delete non-essential cookies already set.")
            elif rck:
                by_script = [c for c in rck if c["vendor"].split()[0].lower() in libv]
                other = [c for c in rck if c not in by_script]
                ev = []
                if by_script:
                    ev.append(cdesc(by_script) + ": the vendor's script was still downloaded after 'Reject' and the cookie "
                              "was rewritten, but no tracking calls were seen")
                if other:
                    ev.append(cdesc(other) + ": no requests to the vendor were seen after 'Reject', so a site script or a "
                              "server response rewrote it")
                if rsoft:
                    ev.append("Consent-denied pings: " + "; ".join(vd(v) for v in rsoft))
                self.add("C-REJECTED", "consent", "high", "Tracking cookie rewritten after the visitor clicks 'Reject'", "law", RR,
                         " | ".join(ev), "Stop the script or server response that writes this cookie after refusal (for example a "
                         "tag manager tag or server-side tagging), and delete the cookie when the visitor rejects.")
            elif rsoft:
                self.add("C-REJECTED", "consent", "medium", "Cookieless Google pings continue after 'Reject'", "law", RR,
                         "; ".join(vd(v) for v in rsoft), "Consider Consent Mode 'basic' so nothing is sent after refusal.")
            elif rleft or rlib:
                ev = []
                if rleft:
                    ev.append("Cookies set before the choice are not removed: " + ", ".join(c["name"] + " (" + c["vendor"] + ")" for c in rleft[:12]))
                if rlib:
                    ev.append("Scripts still downloaded: " + "; ".join(vd(v) for v in rlib))
                self.add("C-REJECTED", "consent", "low", "After 'Reject', no tracking calls were seen but tracking code or cookies remain",
                         "law", RR, "Clicked " + str(d["rejected"]) + ". " + " | ".join(ev),
                         "Delete non-essential cookies when the visitor rejects, and do not load tracking scripts after refusal.")
            else:
                self.ok("C-REJECTED", "consent", "'Reject' is honoured", "law", RR,
                        "Clicked " + str(d["rejected"]) + "; no non-essential trackers or tracking cookies afterwards.")
        elif "reject" in kinds:
            self.na.append("What happens after 'Reject' (automatic click failed or test skipped)")

    def _fingerprint(self):
        by = {}
        for h in self.d.get("fp", []):
            by.setdefault(h.get("src") or "inline script", set()).add(h.get("api"))
        third, first, weak = [], [], []
        for src, apis in by.items():
            strong = "audio" in apis or {"canvas", "webgl"} <= apis
            meta = classify(src) if src.startswith("http") else None
            ext = src.startswith("http") and site_of(host_of(src)) != self.site and not (meta and meta[1] == "security")
            label = src + " [" + ", ".join(sorted(apis)) + "]"
            if strong:
                (third if ext else first).append(label)
            elif "canvas" in apis:
                weak.append(label)
        REF = "PDPL Art. 1 (electronic identifier); Art. 4; Art. 5(1)"
        if third:
            self.add("C-FINGERPRINT", "consent", "high", "Third-party device fingerprinting before consent", "law", REF,
                     "; ".join(third[:5]), "Remove or consent-gate these scripts; fingerprints identify a device without cookies.")
        elif first:
            self.add("C-FINGERPRINT", "consent", "low", "Fingerprint-style browser checks (own or anti-fraud scripts)", "law", REF,
                     "; ".join(first[:5]), "Confirm the purpose and disclose it in the privacy notice.")
        else:
            self.ok("C-FINGERPRINT", "consent", "No device fingerprinting detected", "law", REF, "No canvas/WebGL/audio fingerprint pattern.")
        if weak:
            self.add("C-CANVAS", "advisory", "info", "Canvas reads seen (usually harmless, e.g. emoji support checks)", "advisory",
                     REF, "; ".join(weak[:5]), "Review only if the script is unfamiliar.")

    def _forms(self):
        fi = {"n": 0, "sens": set(), "ids": False, "news": False}
        miss, miss_s, prechk, insecure, seen = [], [], [], [], set()
        weak_only = True                                 # every ordinary form missing a notice has a page-level privacy link
        for f in self.d.get("forms", []):
            sig = tuple(sorted(x["name"] or x["id"] or x["type"] for x in f["fields"]))
            if sig in seen:
                continue
            seen.add(sig)
            if re.search(r"newsletter|subscribe|النشرة", f.get("text", ""), re.I):
                fi["news"] = True
            c = form_info(f)
            if c is None:
                continue
            if c["prechecked"]:
                prechk.append(f["page"] + ": " + "; ".join(c["prechecked"][:3]))
            if not (c["pii"] or c["sens"]):
                continue
            fi["n"] += 1
            fi["sens"].update(c["sens"])
            fi["ids"] = fi["ids"] or c["ids"]
            where = f["page"] + " (fields: " + ", ".join(c["pii"] + c["sens"]) + ")"
            if not c["notice"]:
                if c["plink"]:
                    where += " - only a general privacy link elsewhere on the page (e.g. footer)"
                elif not c["sens"]:
                    weak_only = False
                (miss_s if c["sens"] else miss).append(where)
            if c["insecure"]:
                insecure.append(f["page"])
        REF = "PDPL Art. 13(2) (purposes, recipients and transfer safeguards before processing); Art. 5(1)"
        if miss_s:
            self.add("F-NOTICE-SENSITIVE", "collection", "high" if all("general privacy link" in m for m in miss_s) else "critical", "Sensitive data collected with no privacy notice on the form",
                     "law", REF + "; Art. 1 (Sensitive Personal Data)", " | ".join(miss_s[:5]),
                     "Add a short notice and privacy-notice link next to the submit button, and get explicit consent.")
        if miss:
            self.add("F-NOTICE", "collection", "medium" if weak_only else "high",
                     "Forms collect personal data with no privacy notice nearby", "law", REF,
                     " | ".join(miss[:6]), "Add one line by the submit button: purpose, who receives the data (including "
                     "outside the UAE), and a link to the privacy notice. Check each form manually to confirm.")
        if fi["n"] and not (miss or miss_s):
            self.ok("F-NOTICE", "collection", "Forms link to the privacy notice", "law", REF, str(fi["n"]) + " personal-data form(s) checked.")
        if not fi["n"]:
            self.na.append("Notices on forms (no personal-data forms found on the scanned pages)")
        if prechk:
            self.add("C-PRECHECK-FORM", "consent", "high", "Consent or marketing boxes ticked by default in forms", "law",
                     "PDPL Art. 1 (Consent); Art. 6(1)(b); Art. 17(1)", " | ".join(prechk[:5]),
                     "Leave consent and marketing boxes unticked; keep marketing consent separate from terms.")
        if insecure:
            self.add("S-FORM-HTTP", "security", "high", "Personal data sent over unencrypted HTTP", "law",
                     "PDPL Art. 20(1)(a); Art. 5(6)", " | ".join(insecure[:5]), "Serve every page and form over HTTPS only.")
        return fi

    def _arabic(self, pol):
        return arabic_evidence(pol, self.d["home"])

    def _notice(self, fi):
        d, pol = self.d, self.d.get("policy", {})
        T = "PDPL Art. 5(1) (fair, transparent and lawful processing); Art. 13(2)"
        if not pol.get("found"):
            if pol.get("linked") and pol.get("blocked"):
                # The homepage links to a notice but the site refused the scanner: do not report "no notice".
                why = "; ".join(pol["blocked"][:3])
                self.add("N-UNREAD", "advisory", "info", "Privacy notice is linked but the scanner could not read it - check manually",
                         "advisory", T, why, "Open the notice in a browser and review it against PDPL Art. 13, or re-scan "
                         "through a UAE proxy.")
                for k in ("notice", "rights", "governance"):
                    self.unassessed[k] = "notice could not be read"
                self.na.append("Privacy-notice content checks (the notice is linked but could not be read: " + why + ")")
                return
            tried = ", ".join(pol.get("tried", [])[:6])
            self.add("N-FOUND", "notice", "critical", "No privacy notice found", "law", T,
                     "Nothing found via homepage links or common addresses. Checked: " + (tried or "no candidate pages") + ".",
                     "Publish a standalone privacy notice covering PDPL Art. 13 (purposes, recipients, transfers abroad, "
                     "retention, rights and a contact route for privacy requests), linked from every page footer and form.")
            for k in ("rights", "governance"):
                self.unassessed[k] = "no privacy notice"
            self.na.append("Privacy-notice content checks, rights and complaint wording (no notice found)")
            return
        full = pol.get("main") or pol.get("text", "")
        clean = [ln.strip() for ln in full.splitlines() if ln.strip() and not TOC_RE.search(ln) and not PLACEHOLDER_RE.search(ln)]
        body = [ln for ln in clean if len(ln.split()) >= 8 and not DEF_RE.search(ln)]
        self.ptext, self.pbody = full, body
        words = len(full.split())
        urls = pol.get("urls") or [pol["url"]]
        where = urls[0] + ((" and " + ", ".join(urls[1:]) + " (read together)") if len(urls) > 1 else "")
        self.ok("N-FOUND", "notice", "Privacy notice found", "law", T, where + " (" + str(words) + " words of main text)")
        if not pol.get("linked"):
            self.add("N-LINKED", "notice", "medium", "Privacy notice not linked from the homepage", "law", T,
                     "Found only by trying " + pol["url"], "Link the notice from the footer of every page.")
        if words < 400:
            self.add("N-BRIEF", "notice", "medium", "Privacy notice is very short", "law", "PDPL Art. 13(1)",
                     str(words) + " words - unlikely to cover the Art. 13(1) items.", "Expand it to cover each Art. 13(1) item.")
        ph = PLACEHOLDER_RE.search(full)
        if ph:
            self.add("N-PLACEHOLDER", "notice", "medium", "Unfinished placeholder text in the privacy notice", "law",
                     "PDPL Art. 5(1) (transparency); Art. 19", snip(full, ph),
                     "Replace the placeholder with the real details (legal entity, registered address, contacts).")
        ar = self._arabic(pol)
        if ar:
            self.ok("N-ARABIC", "notice", "Arabic version available", "best", "Best practice (Arabic is the official language)", ar)
        else:
            self.add("N-ARABIC", "notice", "low", "No Arabic version of the privacy notice found", "best",
                     "Best practice; supports Art. 5(1)", "No Arabic notice text, Arabic page version or language link found.",
                     "Publish the privacy notice and consent banner in Arabic as well as English.")
        laws = [(n, len(re.findall(p, full, re.I))) for n, p in FOREIGN_LAWS]
        laws = [(n, k) for n, k in laws if k]
        uae = UAE_REF_RE.search(full) or (re.search(r"\bPDPL\b", full) and re.search(r"\bUAE\b|United Arab Emirates|الإمارات", full))
        if uae:
            self.ok("N-PDPL", "notice", "UAE PDPL referenced", "best", "Best practice (localisation)", snip(full, uae))
        elif laws and not self._uae_signals()[0]:
            names = " and ".join(n for n, _ in laws)
            self.add("N-JURISDICTION", "advisory", "info", "Privacy notice is written for " + names + " (no link to the UAE found)",
                     "advisory", "PDPL Art. 2(1); Art. 13", "The notice refers to " + ", ".join(n + " (" + str(k) + " mentions)" for n, k in laws) +
                     ". No sign was found that the organisation serves people in the UAE.",
                     "If the organisation serves people in the UAE, add a UAE section under Federal Decree-Law No. 45 of 2021.")
            self.law_note = " [Note: written for " + names + "; confirm this wording also meets the PDPL.]"
        elif laws:
            names = " and ".join(n for n, _ in laws)
            self.add("N-JURISDICTION", "notice", "high" if max(k for _, k in laws) >= 3 else "medium",
                     "Privacy notice is written for " + names + ", not the UAE PDPL", "law", "PDPL Art. 13; Art. 5(1)",
                     "The notice refers to " + ", ".join(n + " (" + str(k) + " mentions)" for n, k in laws) +
                     " and never to the UAE PDPL or the UAE Data Office.",
                     "Publish a UAE notice (or UAE section) under Federal Decree-Law No. 45 of 2021: PDPL rights, complaints "
                     "to the UAE Data Office, Art. 22-23 transfer safeguards, and no reliance on legitimate interests.")
            self.law_note = " [Note: written for " + names + "; confirm this wording also meets the PDPL.]"
        else:
            self.add("N-PDPL", "notice", "low", "UAE PDPL not referenced", "best", "Best practice (localisation)",
                     "The notice does not mention the UAE PDPL or the UAE Data Office.",
                     "Reference Federal Decree-Law No. 45 of 2021 and the UAE Data Office.")
        any_ne = any(v["cat"] in NON_ESSENTIAL for v in d["v_all"].values())
        for fid, cat, sev, basis, ref, title, rxs, fix in CHECKS:
            if fid == "X-TRANSFER":
                continue
            lines = clean if fid in FULL_SCOPE else body
            found = [h for h in (find_best(r, lines) for r in rxs) if h]
            if fid == "N-SENSITIVE":
                if not fi["sens"] and not found:
                    continue
                if fi["sens"]:
                    sev = "medium"
            if fid == "N-COOKIES" and any_ne:
                sev = "medium"
            if fid == "G-DPO":
                if found:
                    self.ok(fid, cat, title, basis, ref, ev_of(found[0]))
                else:
                    self.add(fid, "advisory", "info", "No Data Protection Officer named", "advisory", ref,
                             "The privacy notice does not name a DPO.", fix)
                continue
            if len(found) == len(rxs) and fid == "N-UPDATED":
                ev = ev_of(found[0])
                for i, ln in enumerate(lines):                 # quote the line that carries the actual date
                    if rxs[0].search(ln):
                        nxt = lines[i + 1] if i + 1 < len(lines) else ""
                        if DATE_RE.search(ln) and len(ln) < 200:
                            ev = ln
                            break
                        if len(ln) < 60 and DATE_RE.search(nxt) and len(nxt) < 60:
                            ev = ln + " " + nxt
                            break
                self.ok(fid, cat, title, basis, ref, ev + self.law_note)
                continue
            if len(found) == len(rxs):
                best = found[0]
                if fid in PREFER:
                    extra = (PREFER[fid], PD_RE) if fid == "N-RECIPIENTS" else (PREFER[fid],)
                    best = best_sentence(rxs[0], lines, extra) or best
                self.ok(fid, cat, title, basis, ref, ev_of(best) + self.law_note)
                continue
            if found:
                self.add(fid, cat, "medium" if sev in ("critical", "high") else "low", title + " (partly covered)", basis, ref,
                         "Only part of this was found: " + ev_of(found[0]), fix)
                continue
            if fid == "G-COMPLAINT":
                g = find_best(GENERIC_COMPLAINT_RE, body)
                if g:
                    self.add(fid, cat, "low", title + " (generic authority only)", basis, ref, ev_of(g), fix)
                    continue
            ev = "No matching wording found in the main text of the privacy notice."
            if fid == "R-MARKETING":
                if MARKETING_RE.search(full) or fi["news"]:
                    sev = "medium"
                else:
                    sev, ev = "low", "No marketing opt-out wording found (only required if you send direct marketing)."
            self.add(fid, cat, sev, title + " - not found", basis, ref, ev, fix)
        lg = find_best(LEGIT_RE, body)
        if lg and not re.search(r"\b(not|never|no)\b[^.]{0,30}legitimate interest", lg[0], re.I):
            self.add("N-LEGIT", "notice", "medium", "Notice relies on 'legitimate interests'", "law",
                     "PDPL Art. 4 (closed list of grounds besides consent)", ev_of(lg),
                     "The PDPL has no legitimate-interests ground. Map each such purpose to consent or a specific Art. 4 exception.")
        emails = sorted({x for x in EMAIL_RE.findall(full) if not re.search(r"\.(png|jpe?g|gif|svg|webp)$", x, re.I)})[:5]
        mails = [l["href"][7:] for l in pol.get("links", []) if l["href"].lower().startswith("mailto:")][:3]
        route = find_best(REQUEST_ROUTE_RE, clean)
        clinks = [l for l in pol.get("mlinks", []) if site_of(host_of(l["href"])) == self.site and
                  re.search(r"contact|request|dsar|data-?subject|privacy-?(portal|centre|center)|exercise", l["href"] + " " + l["text"], re.I)]
        if emails or mails:
            self.ok("R-CONTACT", "rights", "Contact route for privacy requests", "law", "PDPL Art. 19", "Emails: " + ", ".join(emails or mails))
        elif route:
            self.ok("R-CONTACT", "rights", "Contact route for privacy requests", "law", "PDPL Art. 19",
                    "Request route in the notice: " + ev_of(route))
        elif clinks:
            self.ok("R-CONTACT", "rights", "Contact route for privacy requests", "law", "PDPL Art. 19",
                    "Contact page linked from the notice: " + ", ".join(sorted({l["href"] for l in clinks})[:3]))
        else:
            self.add("R-CONTACT", "rights", "high", "No clear way to send privacy requests", "law", "PDPL Art. 19",
                     "No email address, request form or contact link found in the privacy notice.",
                     "Add a privacy email address or request form to the notice.")

    def _transfers(self):
        d = self.d
        chk = next(c for c in CHECKS if c[0] == "X-TRANSFER")
        foreign = [v for v in d["v_all"].values() if v["cc"] not in ("AE", "??")]
        unknown = sorted({h for vs in (d["v_all"], d.get("v_rej") or {}) for v in vs.values() if v["cat"] == "unclassified"
                          for h in v["domains"]})
        by = {}
        for v in foreign:
            by.setdefault(v["cc"], set()).add(v["vendor"])
        seen = "; ".join(cc + ": " + ", ".join(sorted(vs)) for cc, vs in sorted(by.items()))
        hit = find_best(chk[6][0], self.pbody) if self.pbody else None
        if "notice" in self.unassessed:
            self.na.append("Disclosure of transfers abroad in the privacy notice (notice could not be read)")
        elif hit and not any(re.search(r"\bUAE\b|United Arab Emirates|الإمارات", ln) for ln in self.pbody if chk[6][0].search(ln)) and \
                all(re.search(r"\bEEA\b|European Economic Area|\bEU\b|European Union|\bUK\b", ln) for ln in self.pbody if chk[6][0].search(ln)):
            self.add("X-TRANSFER", "cross_border", "medium", "Transfers abroad are described only for the EU/EEA, not for the UAE", "law",
                     chk[4], ev_of(hit), "Add the UAE view: which countries data goes to from the UAE and the safeguard used "
                     "(a Data Office-approved country under Art. 22, or a contract / explicit consent under Art. 23).")
        elif hit:
            self.ok("X-TRANSFER", "cross_border", chk[5], "law", chk[4], ev_of(hit) + self.law_note)
        elif foreign:
            self.add("X-TRANSFER", "cross_border", "high", "Data goes to vendors outside the UAE but transfers are not disclosed",
                     "law", chk[4], "Vendors by headquarters country - " + seen, chk[7])
        elif self.pbody:
            self.add("X-TRANSFER", "cross_border", "low", chk[5] + " - not found", "law", chk[4],
                     "No foreign vendors seen on the website, but hosting, CRM and email tools are often abroad.", chk[7])
        if foreign:
            self.add("X-MECHANISM", "advisory", "info", "Confirm a legal transfer route for each foreign vendor", "advisory",
                     "PDPL Art. 22 (approved countries); Art. 23 (contract, explicit consent, other cases)", seen,
                     "Record for each country whether the transfer relies on Art. 22 or an Art. 23 route.")
        if unknown:
            pre = {h for v in d["v_pre"].values() if v["cat"] == "unclassified" for h in v["domains"]}
            rej = {h for v in (d.get("v_rej") or {}).values() if v["cat"] == "unclassified" for h in v["domains"]}
            self.add("X-UNKNOWN", "advisory", "info", "Unidentified third-party domains - review", "advisory",
                     "PDPL Art. 13(1)(d); Art. 4", ", ".join(h + (" (before consent)" if h in pre else " (after 'Reject')" if h in rej else "")
                                                            for h in unknown[:15]),
                     "Identify each operator and its location. If one tracks visitors, load it only after consent.")

    def _security(self):
        d, h = self.d, self.d.get("headers", {})
        https, tls, hr = d["final"].startswith("https://"), d.get("tls", {}), d.get("http", {})
        R = "PDPL Art. 20(1)(a)-(b) (security to best international practice); Art. 5(6)"
        BP = "Best practice; supports PDPL Art. 20"
        if not https:
            self.add("S-HTTPS", "security", "critical", "Site served over plain HTTP", "law", R, d["final"], "Serve the whole site over HTTPS.")
        elif hr.get("redirect") is False:
            self.add("S-HTTPS", "security", "high", "HTTP is not redirected to HTTPS", "law", R,
                     "http:// answered " + str(hr.get("status")) + " without redirecting.", "301-redirect all HTTP traffic to HTTPS.")
        else:
            self.ok("S-HTTPS", "security", "HTTPS enforced", "law", R, hr.get("location") or "Final address is HTTPS")
        if tls.get("valid") is False:
            self.add("S-CERT", "security", "high", "TLS certificate invalid", "law", R, tls.get("error", ""), "Install a valid certificate.")
        elif tls.get("valid") and tls.get("days", 999) < 15:
            self.add("S-CERT", "security", "low", "TLS certificate expires within 15 days", "law", R, "Expires " + tls["expires"], "Renew it now.")
        elif tls.get("valid"):
            self.ok("S-CERT", "security", "Valid TLS certificate", "law", R, str(tls.get("version")) + ", expires " + tls["expires"])
        if tls.get("version") in ("TLSv1", "TLSv1.1") or tls.get("legacy"):
            self.add("S-TLS", "security", "medium", "Old TLS 1.0/1.1 still accepted", "law", R,
                     "Accepted: " + str(tls.get("legacy") or tls.get("version")),
                     "Allow TLS 1.2 and 1.3 only (in a CDN such as Cloudflare, set Minimum TLS Version to 1.2). "
                     "Confirm with ssllabs.com/ssltest before reporting.")
        hsts = h.get("strict-transport-security", "")
        m = re.search(r"max-age=(\d+)", hsts)
        if https and not hsts:
            self.add("S-HSTS", "security", "medium", "HSTS header missing", "law", R, "Strict-Transport-Security not sent.",
                     "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")
        elif https and (not m or int(m.group(1)) < 15552000):
            self.add("S-HSTS", "security", "low", "HSTS max-age below 180 days", "law", R, hsts, "Raise max-age to 31536000.")
        elif https:
            self.ok("S-HSTS", "security", "HSTS enabled", "law", R, hsts)
        csp = h.get("content-security-policy", "")
        if not csp:                                        # a CSP can also be set with <meta http-equiv>
            for tag in re.findall(r"<meta\b[^>]*>", d["home"].get("html", ""), re.I):
                if re.search(r"http-equiv\s*=\s*[\"']?content-security-policy[\"'\s>]", tag, re.I):
                    mc = re.search(r"content\s*=\s*([\"'])(.*?)\1", tag, re.I | re.S)
                    if mc:
                        csp = html.unescape(mc.group(2))
                        break
        hdr_csp = h.get("content-security-policy", "")
        dirs = {p.strip().split()[0].lower(): p.strip() for p in csp.split(";") if p.strip()}
        hdr_dirs = {p.strip().split()[0].lower(): p.strip() for p in hdr_csp.split(";") if p.strip()}
        script_src = dirs.get("script-src") or dirs.get("default-src")
        if not csp and h.get("content-security-policy-report-only"):
            self.add("S-CSP", "security", "low", "Content-Security-Policy is in report-only mode (not enforced)", "law", R,
                     "Content-Security-Policy-Report-Only: " + h["content-security-policy-report-only"][:160],
                     "Switch the policy to enforcing mode (Content-Security-Policy) once the reports are clean.")
        elif not csp:
            self.add("S-CSP", "security", "medium", "Content-Security-Policy missing", "law", R, "Header not sent.",
                     "Add a CSP limiting which scripts can run; it also limits which third parties receive data.")
        elif not script_src:
            self.add("S-CSP", "security", "low", "Content-Security-Policy does not restrict scripts", "law", R, csp[:200],
                     "Add a script-src (or default-src) directive listing the allowed script sources.")
        elif "'unsafe-inline'" in script_src and not re.search(r"'nonce-|'sha\d{3}-|'strict-dynamic'", script_src):
            self.add("S-CSP", "security", "low", "CSP allows inline scripts", "law", R, csp[:200], "Use nonces or hashes instead of 'unsafe-inline'.")
        else:
            self.ok("S-CSP", "security", "Content-Security-Policy restricts scripts", "law", R, csp[:200])
        for bad, fid, title, basis, ref, fix in [
                (not h.get("x-frame-options") and "frame-ancestors" not in hdr_dirs, "S-FRAME", "No clickjacking protection", "law", R,
                 "Add CSP frame-ancestors 'self' or X-Frame-Options."),
                (h.get("x-content-type-options", "").strip().lower() != "nosniff", "S-NOSNIFF", "X-Content-Type-Options missing", "law", R,
                 "Add 'X-Content-Type-Options: nosniff'."),
                (h.get("referrer-policy", "").strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"), "S-REFERRER",
                 "Referrer-Policy leaks full page addresses to third parties", "best", BP, "Use strict-origin-when-cross-origin."),
                (not h.get("permissions-policy"), "S-PERMS", "Permissions-Policy missing", "best", BP, "Disable unused browser features.")]:
            if bad:
                self.add(fid, "security", "low", title, basis, ref, "Response headers of " + d["final"], fix)
        ver = [k + ": " + h[k] for k in ("server", "x-powered-by") if VERSION_RE.search(h.get(k, ""))]
        if ver:
            self.add("S-VERSION", "security", "low", "Server software versions disclosed", "best", BP, "; ".join(ver), "Hide version numbers.")
        ck = d.get("ck_acc") or d.get("ck_pre") or []
        tracked = {c["name"] for c in track_cookies(ck)}
        mine = [c for c in ck if site_of(c.get("domain", "").lstrip(".")) == self.site and c["name"] not in tracked]
        nosec = sorted({c["name"] for c in mine if https and not c.get("secure")})
        noho = sorted({c["name"] for c in mine if re.search(r"sess|sid$|auth|token|jwt|login", c["name"], re.I)
                       and not re.search(r"csrf|xsrf", c["name"], re.I) and not c.get("httpOnly")})
        if nosec:
            self.add("S-COOKIE", "security", "low", "Site cookies without the Secure flag", "law", R, ", ".join(nosec[:10]),
                     "Set the Secure flag on the site's own cookies.")
        if noho:
            self.add("S-COOKIE-JS", "security", "low", "Session cookies readable by scripts", "law", R, ", ".join(noho[:10]),
                     "Set HttpOnly on session and login cookies.")
        mixed = sorted(set(MIXED_RE.findall(d["home"].get("html", ""))))[:6] if https else []
        if mixed:
            self.add("S-MIXED", "security", "medium", "Insecure HTTP content on HTTPS pages", "law", R, ", ".join(mixed), "Load everything over HTTPS.")
        if d.get("sectxt"):
            self.ok("S-SECTXT", "security", "security.txt published", "best", BP, "/.well-known/security.txt")
        else:
            self.add("S-SECTXT", "security", "low", "No security.txt file", "best", BP, "/.well-known/security.txt not found",
                     "Publish a security.txt with a security contact.")

    def _uae_signals(self):
        """Signs that the organisation serves people in the UAE (PDPL Art. 2(1)). Returns (signals, UAE page link)."""
        d, c = self.d, self.client
        home = d["home"].get("text", "")
        stated = (c.get("industry", "") + " " + c.get("emirate", "")).strip()
        host = host_of(d["final"])
        uae_link = ""
        already_uae = bool(UAE_PATH_RE.search(urlparse(d["final"]).path)) or \
            bool(re.search(r"[-_]ae$", (d["home"].get("lang") or "").strip(), re.I))    # e.g. <html lang="en-AE">
        if not already_uae:
            for l in d["home"]["links"]:
                u = urlparse(l["href"])
                if site_of(u.hostname or "") == self.site and (UAE_PATH_RE.search(u.path or "") or (u.hostname or "").startswith(("ae.", "uae."))):
                    uae_link = l["href"]
                    break
        hay = home + "\n" + self.ptext + "\n" + stated
        sig = [s for s, hit in [(".ae domain", host.endswith(".ae")), ("UAE version of the site", already_uae),
                                ("UAE regional page", bool(uae_link)),
                                ("+971 phone number", bool(re.search(r"\+971|00971", hay))),
                                ("UAE locations mentioned", bool(re.search(r"\b(UAE|United Arab Emirates|Dubai|Abu Dhabi|Sharjah|Ajman|Ras Al Khaimah|Fujairah|Umm Al Quwain)\b|الإمارات|دبي|أبوظبي", hay, re.I))),
                                ("Middle East / GCC references", bool(re.search(r"Middle East|\bGCC\b|\bMENA\b|الشرق الأوسط", home, re.I))),
                                ("AED prices", bool(re.search(r"\bAED\b|درهم", hay)))] if hit]
        return sig, uae_link

    def _advisories(self, fi):
        d, c = self.d, self.client
        home = d["home"].get("text", "")
        stated = (c.get("industry", "") + " " + c.get("emirate", "")).strip()
        host = host_of(d["final"])
        for fid, pat, src, title, fix in [
                ("A-DIFC", r"\bDIFC\b|Dubai International Financial Cent", home + "\n" + stated,
                 "DIFC link found - check which law applies",
                 "Entities established in the DIFC fall under DIFC Data Protection Law No. 5 of 2020 instead of the PDPL (Art. 2(2)(g))."),
                ("A-ADGM", r"\bADGM\b|Abu Dhabi Global Market", home + "\n" + stated, "ADGM link found - check which law applies",
                 "Entities established in ADGM fall under the ADGM Data Protection Regulations 2021 instead of the PDPL (Art. 2(2)(g))."),
                ("A-HEALTH", r"health|hospital|clinic|medical|pharma|صحي|طبي", stated, "Healthcare client - check the health-data exclusion",
                 "Health data covered by its own legislation is excluded from the PDPL (Art. 2(2)(e)); confirm which law applies."),
                ("A-BANK", r"bank|financ|credit|lending|exchange house|مصرف|بنك", stated, "Banking/finance client - check the banking-data exclusion",
                 "Banking and credit data covered by its own legislation is excluded from the PDPL (Art. 2(2)(f))."),
        ]:
            m = re.search(pat, src, re.I)
            if m:
                self.add(fid, "advisory", "info", title, "advisory", "PDPL Art. 2(2)", snip(src, m), fix)
        if host.endswith(".gov.ae"):
            self.add("A-GOV", "advisory", "info", "Government website", "advisory", "PDPL Art. 2(2)(a)-(b)", host,
                     "The PDPL excludes government entities; emirate-level data laws may apply instead.")
        sig, uae_link = self._uae_signals()
        if uae_link:
            self.add("A-UAEPAGE", "advisory", "info", "This website has a UAE version - scan that page for a UAE report", "advisory",
                     "PDPL Art. 2(1)", uae_link, "Re-run the scan on " + uae_link + " so the UAE privacy notice and banner are assessed.")
        self.add("A-SCOPE", "advisory", "info", "Link to the UAE: " + ", ".join(sig) if sig else "No link to the UAE found", "advisory",
                 "PDPL Art. 2(1) (covers organisations in the UAE and those abroad handling data of people in the UAE)",
                 ", ".join(sig) or "None found", "Confirm the PDPL applies to this client.")
        if fi["sens"]:
            self.add("A-DPIA", "advisory", "info", "Sensitive data collected - check DPIA and DPO duties", "advisory",
                     "PDPL Art. 21(2)(b); Art. 10(1)(b)-(c)", "Sensitive data in forms: " + ", ".join(sorted(fi["sens"])),
                     "Assess whether the volume requires a DPIA and a DPO, and document the decision.")
        if fi["ids"]:
            self.add("A-IDS", "advisory", "info", "Emirates ID or passport collected - check it is necessary", "advisory",
                     "PDPL Art. 5(3) (only data that is necessary)", "ID document fields or uploads found in forms.",
                     "Collect ID documents only where the service or a law requires it; limit access and retention.")
        k = CHILD_RE.search(home)
        if k:
            self.add("A-CHILD", "advisory", "info", "Child-related content" + (" (age check seen)" if AGEGATE_RE.search(home) else " (no age check seen)"),
                     "advisory", "Federal Decree-Law No. 26 of 2025 on Child Digital Safety (child = under 18)", snip(home, k),
                     "If children in the UAE use the service, assess the Child Digital Safety Law: age verification, "
                     "high-privacy defaults for children, and limits on targeted advertising to children.")

    def report(self):
        d, cats = self.d, {}
        no_notice = any(f.id == "N-FOUND" and not f.passed for f in self.res)
        for k, (label, w) in CATS.items():
            if k in self.unassessed:
                cats[k] = {"label": label, "weight": w, "score": None, "note": self.unassessed[k]}
                continue
            ded = sum(DEDUCT[f.sev] for f in self.res if f.cat == k and not f.passed and f.basis != "advisory")
            score = 0 if (k == "notice" and no_notice) else max(0, 100 - ded)
            cats[k] = {"label": label, "weight": w, "score": score}
        scored = [c for c in cats.values() if c["score"] is not None]
        raw = round(sum(c["score"] * c["weight"] for c in scored) / max(1, sum(c["weight"] for c in scored)))
        fails = sorted((f for f in self.res if not f.passed and f.basis != "advisory"), key=lambda f: (ORDER[f.sev], f.cat))
        counts = {s: sum(1 for f in fails if f.sev == s) for s in ("critical", "high", "medium", "low")}
        cap, cap_note = 100, ""
        if counts["critical"]:
            cap, cap_note = 59, "Grade capped at C because critical gaps were found"
        elif counts["high"] >= 3:
            cap, cap_note = 79, "Grade capped at B because three or more high-severity gaps were found"
        elif "notice" in self.unassessed:
            cap, cap_note = 79, "Grade capped at B because the privacy notice could not be assessed"
        elif "consent" in self.unassessed:
            cap, cap_note = 79, "Grade capped at B because consent and tracking could not be assessed"
        score = min(raw, cap)
        cap_note = (cap_note + " (score before cap: " + str(raw) + ").") if score < raw else ""
        grade, meaning = next((g, m) for lim, g, m in GRADES if score >= lim)
        rows = {}
        for key, flag in (("v_all", None), ("v_pre", "pre"), ("v_acc", "acc"), ("v_rej", "rej")):
            for name, v in (d.get(key) or {}).items():
                r = rows.setdefault(name, {"vendor": name, "cat": v["cat"], "cc": v["cc"], "pre": "", "acc": "", "rej": ""})
                if flag:
                    r[flag] = v["mode"]
        rank = {"tracking": 0, "denied": 1, "script": 2, "": 3}
        return {"score": score, "raw_score": raw, "cap_note": cap_note, "grade": grade, "meaning": meaning, "cats": cats,
                "final_url": d.get("final"), "scanned_at": datetime.now(GST).strftime("%d %B %Y, %H:%M") + " GST (UTC+4)",
                "counts": counts, "findings": [asdict(f) for f in fails],
                "advisories": [asdict(f) for f in self.res if f.basis == "advisory" and not f.passed],
                "passes": [asdict(f) for f in self.res if f.passed],
                "trackers": sorted(rows.values(), key=lambda r: (rank[r["pre"]], r["cat"] not in NON_ESSENTIAL, r["cat"], r["vendor"])),
                "reject_tested": bool(d.get("rejected")), "accept_tested": bool(d.get("accepted")),
                "scope_warning": "" if self._uae_signals()[0] else (
                    "No link to the UAE was found on this website (no .ae domain, UAE address or phone number, AED prices "
                    "or UAE pages). Confirm that the UAE PDPL applies to this organisation before sharing this report."),
                "assess_warning": "" if not self.hidden_tags else (
                    "Tracking tags are set up on this website (" + ", ".join(lab for lab, _ in self.hidden_tags[:4]) + ") but did not "
                    "load for the automated scanner. " + ("The consent and tracking results are not reliable: check them manually "
                    "in a normal browser before sharing this report." if "consent" in self.unassessed else "The consent findings "
                    "below are real, but more trackers may load for real visitors: check manually before sharing this report.")),
                "policy_url": d.get("policy", {}).get("url"),
                "policy_urls": d.get("policy", {}).get("urls"), "timings": self.timings, "parallel": self.parallel,
                "not_covered": self.na + NOT_COVERED}


# ------------------------------------------------------------------ report output
CSS = """
*{box-sizing:border-box}body{margin:0;font:11px/1.5 -apple-system,'Segoe UI',Roboto,Arial,sans-serif;color:#101828}
.cover{min-height:245mm;display:flex;flex-direction:column;justify-content:space-between;page-break-after:always}
.brand{font-size:13px;font-weight:700;color:#175cd3;letter-spacing:.06em}.cover h1{font-size:30px;margin:30mm 0 6px}
.sub{font-size:13px;color:#475467}.kv{width:100%;border-collapse:collapse;margin-top:12mm}
.kv td{padding:7px 0;border-bottom:1px solid #e4e7ec;font-size:12px;vertical-align:top}.kv td:first-child{color:#475467;width:38%}
.big{display:flex;gap:16px;align-items:center}.score{font-size:46px;font-weight:800}
.gr{font-size:18px;font-weight:700;padding:6px 14px;border-radius:8px;color:#fff}.muted{color:#667085}
h2{font-size:16px;margin:18px 0 8px;padding-bottom:4px;border-bottom:2px solid #e4e7ec;page-break-after:avoid}
.note{background:#fffaeb;border:1px solid #fedf89;border-radius:6px;padding:8px 10px;color:#7a2e0e;margin:10px 0}
.bar{display:grid;grid-template-columns:190px 1fr 34px;gap:10px;align-items:center;margin:4px 0}
.track{height:8px;background:#e4e7ec;border-radius:4px;overflow:hidden}.fill{height:100%}
.card{border:1px solid #e4e7ec;border-left:4px solid;border-radius:6px;padding:8px 10px;margin:7px 0;break-inside:avoid}
.card h4{margin:0 0 2px;font-size:12px}.card p{margin:3px 0;word-break:break-word}
.tag{display:inline-block;font-size:9px;font-weight:700;color:#fff;padding:1px 6px;border-radius:9px;margin-right:6px}
.ref{color:#344054;font-weight:600;font-size:10px}ul,ol{margin:4px 0 0 18px;padding:0}li{margin:2px 0}
table.t{width:100%;border-collapse:collapse;font-size:10px}table.t th,table.t td{border-bottom:1px solid #e4e7ec;padding:4px 6px;text-align:left}
table.t th{background:#f2f4f7}
"""


def render(r, c):
    e = html.escape
    gc = {"A": "#067647", "B": "#4d7c0f", "C": "#b54708", "D": "#c4320a", "F": "#b42318"}[r["grade"]]

    def card(f):
        st = "pass" if f["passed"] else f["sev"]
        lab = "PASS" if f["passed"] else ("ADVISORY" if f["basis"] == "advisory" else f["sev"].upper())
        out = ('<div class="card" style="border-left-color:' + COLOR[st] + '"><h4><span class="tag" style="background:' + COLOR[st] + '">'
               + lab + "</span>" + e(f["title"]) + '</h4><div class="ref">' + e(BASIS[f["basis"]]) + " | " + e(f["ref"]) + "</div>"
               + "<p><b>Evidence:</b> " + e(f["evidence"]) + "</p>")
        if f["fix"] and not f["passed"]:
            out += "<p><b>How to fix:</b> " + e(f["fix"]) + "</p>"
        return out + "</div>"

    def dot(mode, cat):
        if not mode:
            return ""
        if cat == "unclassified":
            return "Script only" if mode == "script" else "Calls seen (unidentified)"
        return e(MODE_LABEL.get(mode, mode)) if cat in NON_ESSENTIAL else "Loaded"

    details = [("Client", c["company"]), ("Website scanned", r["final_url"]), ("Contact person", c["contact"]),
               ("Contact email", c["email"]), ("Industry / sector", c["industry"]), ("Emirate / free zone", c["emirate"]),
               ("Prepared by", c["prepared_by"]), ("Scan date", r["scanned_at"]), ("Notes", c["notes"])]
    n = r["counts"]
    cap = ("<div class='muted'>" + e(r["cap_note"]) + "</div>") if r["cap_note"] else ""
    p = ["<!doctype html><html><head><meta charset='utf-8'><style>" + CSS + "</style></head><body>",
         "<section class='cover'><div><div class='brand'>" + e(c["prepared_by"].upper()) + "</div>",
         "<h1>UAE PDPL Website Readiness Report</h1><div class='sub'>" + e(LAW) + "</div><table class='kv'>",
         "".join("<tr><td>" + e(k) + "</td><td>" + e(v) + "</td></tr>" for k, v in details if v), "</table></div>",
         "<div><div class='big'><div class='score'>" + str(r["score"]) + "<span class='muted' style='font-size:18px'>/100</span></div>",
         "<div class='gr' style='background:" + gc + "'>Grade " + r["grade"] + "</div><div class='muted'>" + e(r["meaning"]) + "</div></div>",
         cap, ("<p style='color:#b42318;font-weight:600'>" + e(r["scope_warning"]) + "</p>") if r.get("scope_warning") else "",
         ("<p style='color:#b42318;font-weight:600'>" + e(r["assess_warning"]) + "</p>") if r.get("assess_warning") else "",
         "<p class='muted'>External website scan. Not a legal opinion or a guarantee of compliance.</p></div></section>",
         "<h2>Executive summary</h2><p>The scan found <b>" + str(n["critical"]) + " critical</b>, <b>" + str(n["high"]) + " high</b>, "
         + str(n["medium"]) + " medium and " + str(n["low"]) + " low-severity gaps on " + e(r["final_url"] or "") + ".</p>"]
    if r["cap_note"]:
        p.append("<p>" + e(r["cap_note"]) + "</p>")
    if r["findings"]:
        p.append("<p><b>Top priorities:</b></p><ol>" + "".join("<li><b>" + e(f["sev"].upper()) + ":</b> " + e(f["title"]) + "</li>"
                                                             for f in r["findings"][:6]) + "</ol>")
    if r.get("scope_warning"):
        p.append("<div class='note'><b>Scope.</b> " + e(r["scope_warning"]) + "</div>")
    if r.get("assess_warning"):
        p.append("<div class='note'><b>Manual check needed.</b> " + e(r["assess_warning"]) + "</div>")
    p.append("<div class='note'><b>Regulatory status.</b> " + e(STATUS_NOTE) + "</div><h2>Scores by area</h2>")
    for cat in r["cats"].values():
        if cat["score"] is None:
            p.append("<div class='bar'><span>" + e(cat["label"]) + " <span class='muted'>(" + str(cat["weight"]) + "%)</span></span>"
                     "<span class='muted'>Not assessed: " + e(cat.get("note", "")) + "</span><b>n/a</b></div>")
            continue
        col = "#12b76a" if cat["score"] >= 80 else "#f79009" if cat["score"] >= 50 else "#f04438"
        p.append("<div class='bar'><span>" + e(cat["label"]) + " <span class='muted'>(" + str(cat["weight"]) + "%)</span></span>"
                 "<div class='track'><div class='fill' style='width:" + str(cat["score"]) + "%;background:" + col + "'></div></div><b>"
                 + str(cat["score"]) + "</b></div>")
    p.append("<h2>Findings (" + str(len(r["findings"])) + ")</h2>" + ("".join(card(f) for f in r["findings"]) or "<p>No scored gaps found.</p>"))
    p.append("<h2>Advisories (not scored)</h2>" + ("".join(card(f) for f in r["advisories"]) or "<p>None.</p>"))
    p.append("<h2>Third parties seen on the website</h2><table class='t'><tr><th>Vendor</th><th>Type</th><th>HQ</th>"
             "<th>Before consent</th><th>After Accept</th><th>After Reject</th></tr>")
    p.append("".join("<tr><td>" + e(t["vendor"]) + "</td><td>" + e(t["cat"]) + "</td><td>" + e(t["cc"]) + "</td><td>" + dot(t["pre"], t["cat"])
                     + "</td><td>" + (dot(t["acc"], t["cat"]) if r.get("accept_tested", True) else "not tested") + "</td><td>" + (dot(t["rej"], t["cat"]) if r["reject_tested"] else "not tested")
                     + "</td></tr>" for t in r["trackers"]) or "<tr><td colspan='6'>None observed</td></tr>")
    p.append("</table><p class='muted'>Tracking = data-sending calls seen. Pings (consent denied) = Google Consent Mode calls "
             "marked as denied. Script only = the vendor's code was downloaded but made no calls. Loaded = non-tracking "
             "service (fonts, CDN, security, consent tool). Calls seen (unidentified) = a domain not in the vendor list; "
             "see the advisory for the full address.</p>")
    p.append("<h2>Checks passed (" + str(len(r["passes"])) + ")</h2><ul>"
             + "".join("<li><b>" + e(f["title"]) + "</b> - " + e(f["evidence"][:220]) + "</li>" for f in r["passes"]) + "</ul>")
    p.append("<h2>Not covered by this scan</h2><ul>" + "".join("<li>" + e(x) + "</li>" for x in r["not_covered"]) + "</ul>")
    p.append("<h2>Method and limitations</h2><ul>" + "".join("<li>" + e(x) + "</li>" for x in LIMITS) + "</ul></body></html>")
    return "".join(p)


def to_pdf(page_html, path, footer):
    foot = ('<div style="font-size:8px;color:#667085;width:100%;padding:0 12mm;display:flex;justify-content:space-between;">'
            "<span>" + html.escape(footer) + '</span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>')
    with sync_playwright() as pw:
        br = pw.chromium.launch(args=CHROME_ARGS)
        pg = br.new_page()
        pg.set_content(page_html, wait_until="load")
        pg.pdf(path=str(path), format="A4", print_background=True, display_header_footer=True,
               header_template="<div></div>", footer_template=foot,
               margin={"top": "14mm", "bottom": "16mm", "left": "12mm", "right": "12mm"})
        br.close()


# ------------------------------------------------------------------ client input and main
FIELDS = [("company", "Client company name", True), ("url", "Website to scan (e.g. https://example.ae)", True),
          ("contact", "Client contact person", False), ("email", "Client contact email", False),
          ("industry", "Industry / sector", False), ("emirate", "Emirate or free zone (e.g. Dubai mainland, DMCC, DIFC)", False),
          ("prepared_by", "Prepared by", False), ("notes", "Notes to show on the report", False)]


def get_client(o, interactive):
    c = {k: (getattr(o, k, None) or "").strip() for k, _, _ in FIELDS}
    if interactive:
        print("\n=== UAE PDPL Website Scanner ===   (* = required, press Enter to skip the others)\n")
        for key, label, required in FIELDS:
            default = BRAND if key == "prepared_by" else ""
            while True:
                v = input(label + (" [" + default + "]" if default else "") + (" *" if required else "") + ": ").strip() or default
                if key == "url" and v and not re.match(r"^(https?://)?[\w.-]+\.[a-z]{2,}", v, re.I):
                    print("  That does not look like a website address. Example: https://example.ae")
                    continue
                if v or not required:
                    break
                print("  This field is required.")
            c[key] = v
    c["prepared_by"] = c["prepared_by"] or BRAND
    c["company"] = c["company"] or host_of(c["url"] if "://" in c["url"] else "https://" + c["url"])
    return c


def run(client, o):
    sc = Scan(client, o)
    print("\nScanning " + sc.url + " - this usually takes about a minute...")
    sc.collect()
    print("Analysing results...")
    sc.analyse()
    r = sc.report()
    folder = Path(__file__).resolve().parent / OUTPUT_DIR
    folder.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9]+", "_", client["company"]).strip("_")[:40] or "client"
    stem = slug + "_UAE_PDPL_Report_" + datetime.now(GST).strftime("%Y-%m-%d_%H%M")
    page = render(r, client)
    (folder / (stem + ".json")).write_text(json.dumps({"client": client, "report": r}, indent=2, ensure_ascii=False, default=list),
                                           encoding="utf-8")
    pdf = folder / (stem + ".pdf")
    try:
        to_pdf(page, pdf, client["company"] + " | UAE PDPL website readiness | " + client["prepared_by"])
        print("\nDone in " + str(sc.timings.get("collect", "?")) + "s. Score " + str(r["score"]) + "/100, grade " + r["grade"] + ".")
        print("PDF report saved to: " + str(pdf))
    except Exception as ex:
        alt = folder / (stem + ".html")
        alt.write_text(page, encoding="utf-8")
        print("PDF creation failed (" + str(ex).splitlines()[0] + "). Report saved as HTML instead: " + str(alt))


def main():
    ap = argparse.ArgumentParser(description="UAE PDPL website scanner - creates a PDF report")
    for key, label, _ in FIELDS:
        ap.add_argument("--" + key.replace("_", "-"), dest=key, help=label)
    ap.add_argument("--proxy", help="proxy URL, e.g. http://user:pass@host:port (use a UAE IP for client reports)")
    ap.add_argument("--max-pages", type=int, default=4, help="extra pages to check for forms (default 4)")
    ap.add_argument("--settle", type=int, default=3000, help="minimum ms to wait for trackers after each page load (default 3000)")
    ap.add_argument("--timeout", type=int, default=30000, help="page-load timeout in ms (default 30000)")
    ap.add_argument("--headful", action="store_true", help="show the browser window while scanning")
    ap.add_argument("--no-reject", action="store_true", help="skip the 'Reject' test")
    ap.add_argument("--parallel", choices=["auto", "on", "off"], default=None,
                    help="run the Accept and Reject sessions side by side (default auto: only with 1.5 GB+ memory)")
    o = ap.parse_args()
    interactive = not o.url
    while True:
        client = get_client(o, interactive)
        try:
            run(client, o)
        except Exception as ex:
            print("\n[!] Scan failed: " + str(ex).splitlines()[0])
        if not interactive or input("\nScan another client? (y/n): ").strip().lower() not in ("y", "yes"):
            break
    if interactive:
        input("\nPress Enter to close this window...")


if __name__ == "__main__":
    main()