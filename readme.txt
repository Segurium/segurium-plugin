=== Segurium – Free Malware Removal & Antivirus Scanner, Hacked Website Cleanup, Firewall, 2FA ===
Contributors: segurium
Tags: malware-removal, hacked-website, malware-scanner, virus-removal, antivirus
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.3.2
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Website hacked? Free malware removal and antivirus scan for WordPress: clean infected files, restore them. Firewall, brute force, 2FA included.

== Description ==

**Site hacked? Segurium removes the malware, for free.**

Most security plugins scan the site, name the infected files, and then ask for money to clean them. Segurium does the cleanup. It finds the infected files, removes the malicious code, and puts the original file back, with a reversible encrypted backup. The free tier covers up to 3 cloud cleanups per rolling 30 days, which is enough for a typical incident. No ad walls, no background processes that chew through your shared-hosting CPU budget.

If you are reading this because Google flagged your site, your host suspended the account, or visitors get redirected to a spam page, that is the job this plugin was built for. Segurium finds the malicious code these attacks leave behind in your files: injected redirects, Japanese SEO spam, pharma spam, uploaded shells and backdoors.

= How to clean a hacked WordPress site with Segurium =

1. Install Segurium and accept the service disclosure.
2. Run a malware scan. Files on the server are hashed and checked against the cloud verdict database.
3. Clean the infected files, one at a time or all at once with **Fix All**.
4. Run an integrity scan, and restore any WordPress core, plugin or theme file the attack rewrote.
5. Switch on the firewall, brute-force protection and two-factor authentication so the site does not get hacked again.

A file of yours that an attacker injected code into gets repaired: the injection goes, your content stays. A file that is nothing but malware, such as an uploaded shell, is emptied instead. Either way the original lands in an encrypted local backup first, and one click puts it back.

= A small plugin in front of a large engine =

Segurium hashes your files on the server and checks each against a continuously-updated, machine-learning-curated cloud verdict database — so most files are classified by hash alone, the scan is fast, the plugin stays small, and fresh threats are recognised the moment the classifier picks them up. When a file's hash is not yet known to the cloud, Segurium uploads that file's bytes for deeper analysis so you don't get stuck with an unresolved verdict. Data is only sent with your consent.

= What you get on every install =

Every feature below ships in the plugin and runs on every install — Free and Pro alike:

* **Malware removal and cleanup** — A full filesystem scan finds the infected files; one click strips the malicious code out and keeps an encrypted, reversible backup, so a wrong call is never permanent. A unified "Threats" view collects every finding.
* **Bulk "Fix All" remediation** — Queue every detected threat for cleanup in one click on both malware and integrity panels.
* **Auto-cleanup on detection** — Switch it on and a file that real-time scanning flags is cleaned without waiting for an admin to open the dashboard. Off by default.
* **Real-time and upload scanning** — New and modified files are checked automatically; infected uploads are blocked before they land on disk.
* **Integrity scan** — Verify WordPress core, plugins and themes against upstream manifests, and restore a rewritten file to its official content. That is how you undo a hack that edited legitimate files. Tampered, delisted and abandoned components show up here too.
* **Cleanup with encrypted, reversible backups** — Before anything is cleaned, the original file is encrypted (AES-256-GCM) and stored locally. Backups are retained for up to 30 days, subject to per-bucket count and size caps. "Show original" and "Restore" are one click away.
* **Scheduled scans** — Off / daily / weekly with a locale-aware time picker. Each run chains an integrity check behind the malware pass on the same cadence.
* **Two-factor authentication** — TOTP apps, email fallback, backup codes, trusted devices, per-role enforcement and grace period.
* **Brute-force protection** — Multi-tier lockouts on wp-login.php and XML-RPC, honeypot field, manual IP unlock, optional hCaptcha on login.
* **Firewall** — Allow / deny IP rules, CIDR ranges and country-level filters with a single source-of-truth IP list shared across login, admin and request gating.
* **Geo-blocking** — Block login or admin traffic by country using a local binary database (auto-updated), with a confirm-or-revert safety net so you can't lock yourself out.
* **Security headers** — Security HTTP response headers, cookie hardening (SameSite/Secure/HttpOnly), and five one-click preset modes.
* **Information Shield** — Toggles that hide WordPress version fingerprints, discovery endpoints, asset `?ver=` strings, and XML-RPC when you don't use them.
* **Self-Check security grade** — Checks roll up into an A+ to F grade, each with one-click Fix buttons and cross-referenced with third-party services.
* **Migration importer** — Import your settings from Wordfence, All-In-One Security and Solid Security so you don't lose your hardening when you switch. Sucuri Security is detected too, but its settings live in Sucuri's cloud dashboard and cannot be read locally, so there is nothing to import.
* **Disaster recovery** — Local encrypted backups can be extracted with a tiny PHP one-liner, even if Segurium is uninstalled.
* **Embedded support**.

= How the Pro service tier differs =

Our cloud service performs the cleanups and counts each against a per-installation quota. The Free service tier covers up to **3 cleanups per rolling 30 days** — enough for an occasional incident on a typical site. The Pro service tier raises that quota for sites that need higher volume (recurring infections, hosts under sustained attack, sites with high reliability requirements). The plugin code, the detection engines, and every feature listed above are identical on both tiers; the only difference is the quota ceiling enforced server-side.

= Privacy by default =

* **Scanning is opt-in.** Until you accept the service disclosure on the plugin's admin page, nothing contacts the cloud and the plugin stays idle.
* **Hash-first, body-on-miss.** During a scan, files are checked by SHA-256 first. Only files whose hash is unknown to the cloud have their bytes uploaded for classification, so the volume of content actually leaving your server is small and bounded by what's new on disk.
* **No telemetry on your visitors.** We look at files and security incidents, not at the people who visit your site.
* **On-premise mode.** Switch off cloud-assisted malware detection and scans send hashes, paths and metadata only.

== Installation ==

1. Upload the `segurium` folder to `/wp-content/plugins/`, or install through **Plugins → Add New** in the WordPress admin.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Open **Segurium** in the admin sidebar and accept the service disclosure to enable scanning.
4. (Optional) Import settings from your previous security plugin via **Segurium → Migration**.
5. (Optional) Enable two-factor authentication, geo-blocking and security headers from their respective tabs.

== Frequently Asked Questions ==

= Which security features are free in Segurium that other plugins sell as premium? =

All of them. Two-factor authentication with an authenticator app (TOTP), email codes, backup codes, trusted devices and per-role enforcement. Brute force protection with login attempt limits, lockouts, a honeypot and xmlrpc coverage. A firewall with IP, CIDR and country rules, so you can block a country from your login page. Security headers with HSTS, CSP, Referrer-Policy and Permissions-Policy, plus cookie hardening. Geoblocking from a local database, by country or by preset region (EU, Americas, Asia-Pacific, Africa, Middle East, High-Risk). None of it is a trial and none of it is gated behind a pro plan. Only the number of cloud cleanups is capped on the free tier: three every 30 days.

= Is Segurium an antivirus for a WordPress website? =

In practice, yes. People call the same problem a website virus, a WordPress virus or malware, and it is one thing: files on your server that should not be there, plus code an attacker added to files that should. Segurium hashes the files on your server and asks the cloud verdict database what each one is, so an anti-malware scan of a whole website is a hash lookup rather than a file-by-file inspection. A desktop antivirus protects your laptop. Segurium does that job for your WordPress files, and it removes what it finds.

= Can Segurium replace a paid security plugin? =

For malware removal, two-factor authentication, a firewall, geoblocking and security headers, yes. Those are the parts most plugins sell as a premium subscription, and Segurium ships them free on every install. The paid tier only raises the cloud cleanup quota. If you are moving from another security plugin, the Migration tab imports your settings from Wordfence, All-In-One Security and Solid Security so the switch does not cost you your hardening.

= What does a Segurium scan look for? =

Files the cloud verdict database has already classified as malicious. In a normal break-in that means an uploaded web shell or backdoor, a redirect injected into a theme file, spam pages, hidden links, a phishing page dropped in an upload folder, the Japanese keyword hack, and leftovers from a crypto miner. Segurium does not care what the family is called, whether someone labels it a trojan or a virus. It checks whether a file is malicious and whether it can put the clean version back.

= My WordPress site is hacked. What do I do first? =

Install Segurium, open it from the admin sidebar, accept the service disclosure, and run a malware scan. Segurium lists the infected files and cleans them on one click, keeping an encrypted backup of every original. Then run an integrity scan, so any WordPress core, plugin or theme file the attack rewrote is restored to its official content. Finish by turning on the firewall, brute-force protection and two-factor authentication.

= Does Segurium remove malware for free, or only detect it? =

It removes it. Malware removal runs on the free service tier: up to 3 cloud cleanups per rolling 30 days, enough for a typical incident. Most other plugins report the malware for free and charge for the repair. Every one is reversible from a local encrypted backup.

= How do I clean a hacked WordPress site when I have no backup? =

That is the usual case, and it is what the cleanup engine is for. Where an attacker injected code into a file of yours, Segurium strips the injection and leaves the rest of the file alone. Where the file is nothing but malware, it gets emptied. For WordPress core, plugin and theme files, the integrity scan pulls the official content from upstream manifests, so you get a clean copy even with nothing of your own to restore from.

= Can Segurium fix a Japanese SEO spam, pharma or redirect hack? =

Yes, wherever the infection lives in a file. These hacks inject spam pages, hidden links or redirects into theme, plugin and core files. The scanner flags those files, cleanup strips the injected code, and an integrity pass restores any legitimate file the attack rewrote. Check again afterwards to confirm the site is clean.

= My site redirects visitors to another domain. How do I stop it? =

A WordPress redirect hack is usually a small block of injected code sitting in a theme file, a plugin file or index.php. Run a malware scan and Segurium points at the files carrying the redirect, then cleans them. Follow with an integrity scan to catch a core file that was rewritten.

= Google blacklisted my website or my host suspended it. What now? =

A blacklist entry and a suspension both follow the malicious content, so remove the content first. Run a malware scan, clean the flagged files, then run an integrity scan so any core, plugin or theme file the attack rewrote goes back to its official content. Once the website is clean, request a review in Google Search Console or ask your host to lift the suspension. Segurium does not file those requests for you. It removes the reason for them.

= Will Segurium slow my site down? =

It shouldn't. Scans run in chunked background jobs, behind a lock so a single run can't pile on top of itself. Real-time scanning only inspects new and modified files. The plugin keeps no large tables in memory and ships no bundled binaries.

= What happens if Segurium flags a file that isn't really malware? =

Every cleanup is reversible. Originals are encrypted (AES-256-GCM) and stored locally — retained for up to 30 days, subject to per-bucket count and size caps — and you can restore from backup in one click. You can also submit a **false-positive report** directly from the threats list, and our team uses those to improve classification.

= Does Segurium quarantine suspicious files, and does it check for vulnerabilities? =

There is no separate quarantine folder. Segurium handles a suspicious file in place: it encrypts the original (AES-256-GCM), stores that copy locally, then strips the malicious code out, so the file is neutralised and you can put the original back for up to 30 days. Segurium is not a vulnerability scanner and reads no CVE feed. Its integrity check compares WordPress core, plugins and themes against upstream manifests and flags tampered, delisted and abandoned components, which is where an unpatched or unmaintained component shows up.

= Can I use Segurium alongside my existing security plugin? =

You can, but we recommend migrating. The **Migration** tab imports settings from Wordfence, All-In-One Security and Solid Security so you can switch without losing your hardening. It also detects Sucuri Security, but Sucuri keeps its rules in its own cloud dashboard, so those settings have to be re-entered by hand. Running two security plugins in parallel usually means double the cron overhead for no extra protection.

= Is hCaptcha required for brute-force protection? =

No. Brute-force protection works out of the box with rate limits, honeypot and lockouts. **hCaptcha is optional** — if you already have an hCaptcha site key and secret, you can enable it on the login form for an additional layer. When disabled (the default), no hCaptcha scripts or requests are ever loaded.

= What PHP and WordPress versions are supported? =

PHP 7.4 or newer and WordPress 6.2 or newer. Regularly tested against PHP 8.1 / 8.2 / 8.3 and WordPress 6.3 through 7.0.

= What happens if I uninstall the plugin? =

Plugin options, custom tables and local scan backups are removed. The local encrypted backups remain extractable with a small PHP one-liner before uninstall (see the Disaster Recovery documentation on segurium.com) if you want to keep copies.

= How do I report a security issue in Segurium itself? =

Email security@segurium.com rather than opening a public support topic. Our disclosure policy, testing ground rules and researcher acknowledgements are at https://segurium.com/security/ — it also explains what we can and cannot offer in return. Please keep details private until a fix is available to users.

== External Services ==

Segurium connects to external services to keep your WordPress install protected. Each service is disclosed below with the data that is sent and when. Nothing is sent before you accept the service disclosure on the plugin's admin page.

= Cloud Threat Inspection =

Cloud Threat Inspection, our own service at `cti.segurium.com`, provides malware verdicts, integrity manifests, geo-location data, trusted-proxy IP ranges, support intake, cleanup files, and a per-installation quota on how many files it will clean in a rolling 30-day window. The service is contacted when:

* A malware, integrity, real-time or upload scan is running.
* You act on a plugin page. **Accepting the service disclosure** sends four things at once: a one-time installation registration (a random commitment hash, your site name, your site URL, your WordPress version, and, if you enabled email alerts, the alert email address you entered), a one-line `plugin_activated` ping, a `consent` record, and a first platform snapshot of the kind described below. **Requesting cleanup** of an infected file sends only that file's SHA-256; the cleaned bytes come back by hash. **A support request, false-positive report or missed-malware report** sends the data you typed plus the file bytes you attached. **A settings change** sends a snapshot of that settings group. **Deactivating the plugin** sends a one-line `plugin_deactivated` ping, skipped entirely if you never accepted the disclosure. Activating it sends nothing on its own.
* A daily scheduled job runs. Four of them exist. The GeoIP database update and the trusted-proxies update only fetch data. The component-inventory ping sends your installed plugin/theme slugs and versions and your WordPress version, so we can spot tampered, delisted or abandoned components. The platform snapshot sends how your site is built: your WordPress version, locale, multisite and debug flags, whether WP-Cron is disabled and whether the site is served over HTTPS; your PHP version, SAPI, memory limit, maximum execution time and maximum input vars; your web server and its version; your database engine and version; your operating system family and architecture; the plugin version; and your active theme's slug and version. It carries no file contents, no paths and nothing about your visitors.
* A brute-force lockout, geo-block or other security event fires. That sends a small JSON payload with the event type, your site URL, your domain, your WordPress / PHP / plugin versions, and a SHA-256 hash of the username, never the username itself or the password.

**Data sent during scans** (malware, real-time and upload alike): SHA-256 hashes of files on your server, file paths relative to your WordPress installation, file sizes, file modification times, plugin and theme version strings, and your WordPress version. **For files whose SHA-256 is not yet known to the cloud verdict database, we also upload the file's bytes so the file can be classified.**

**Turning the upload off:** the "Cloud-assisted malware detection" setting on the Settings tab controls it. Switch it off for On-premise mode and scans send hashes, paths and metadata only, so a file whose hash the cloud does not recognise stays unresolved. Two uploads survive that mode, because you pick the file yourself: a false-positive report and a support-ticket attachment.

**Retention:** we keep file samples uploaded for analysis for up to 365 days, then an automated nightly purge removes them. The full schedule is in the privacy policy linked below.

A random installation identifier (IID), issued at registration time, identifies each request. We do not send your posts, pages, or anything about your visitors, and we never send passwords. The privacy policy linked below names the data controller and how to reach them.

* Terms of Service: [https://segurium.com/terms](https://segurium.com/terms)
* Privacy Policy: [https://segurium.com/privacy](https://segurium.com/privacy)

= Freemius (api.freemius.com, checkout.freemius.com, wp.freemius.com) =

Segurium uses the Freemius WordPress SDK (bundled in `freemius/`) for license activation, paid-plan checkout and account management on the Pro plan. The SDK ships in **anonymous mode**: on activation Segurium tells it to skip the connect prompt, so it sends no request to Freemius and collects no telemetry from your install. Freemius, Inc. operates the service.

Freemius servers hear from your site only when you click an upgrade or "Manage billing" button on the account page and complete the checkout on `checkout.freemius.com`, or when you activate, sync or deactivate a Pro license there. In that second case the SDK posts the licence key, your site URL, your WordPress / PHP versions and the plugin version to `api.freemius.com`. Never open the account page and never enter a licence, and your site never calls Freemius at all.

* Freemius Terms of Service: [https://freemius.com/terms/](https://freemius.com/terms/)
* Freemius Privacy Policy: [https://freemius.com/privacy/](https://freemius.com/privacy/)

= hCaptcha (js.hcaptcha.com, hcaptcha.com) — OPTIONAL =

If, and only if, you enable hCaptcha on the brute-force-protection settings page and provide your own hCaptcha site key and secret key, Segurium will:

* Load the hCaptcha JavaScript from `https://js.hcaptcha.com/1/api.js` on the wp-login.php page so the challenge can render.
* Send the hCaptcha token and the visitor's IP address to `https://hcaptcha.com/siteverify` to verify the challenge on login attempts.

hCaptcha is off by default. Until you enable it, no hCaptcha scripts or requests are loaded. hCaptcha is provided by Intuition Machines, Inc.; their terms and privacy policy apply when you enable the feature.

* hCaptcha Terms of Service: [https://www.hcaptcha.com/terms](https://www.hcaptcha.com/terms)
* hCaptcha Privacy Policy: [https://www.hcaptcha.com/privacy](https://www.hcaptcha.com/privacy)

== Source Code of Bundled Libraries ==

Every release is mirrored at https://github.com/Segurium/segurium-plugin.

Segurium ships the Freemius WordPress SDK in `freemius/` for licensing, checkout and support flows. A small number of files inside that SDK (`freemius/assets/js/jquery.form.js` and `freemius/assets/js/postmessage.js`) are minified upstream and shipped as-is. The unminified source for the entire SDK is published under GPL-3.0 at:

* https://github.com/Freemius/wordpress-sdk

The SDK version bundled with this release is recorded in `freemius/start.php` (`$this_sdk_version`).

== Screenshots ==

1. Fix all finished — files cleaned, every original restorable from an encrypted backup. Free tier.
2. The scan that found them — every infected file listed with a Clean button.
3. Security Self-Check — an A+ to F grade with one-click fixes.
4. Integrity scan — per-component status, with Fix and Restore for drifted files.
5. Geo-blocking — preset regions and per-country control.
6. Firewall — IPv4, IPv6 and CIDR lists, proxy ranges auto-detected.
7. Brute-force protection — lockout windows, extended bans, live attack statistics.
8. Two-Factor Authentication — TOTP and email, per-role enforcement, trusted devices.
9. Security headers — presets and cookie hardening, with a live preview.
10. Information Shield — hides the version and discovery metadata WordPress exposes.
11. Migration tool — previews another security plugin's settings before import.
12. Scheduled scans — off, daily or weekly, with email alerts.
13. Plans — $0 forever, 3 cleanups every 30 days; $79 a year per site lifts the cap.

== Changelog ==

= 1.3.2 - 2026-09-04 =
* Some Self-Check fixes apply in place.
* Show a red mark on the Segurium menu and tab when malware or a vulnerable component is present.
* Badge components whose installed release is known vulnerable.
* Show Outdated status and an Update button on the Integrity tab.
* Stop assessing the cookie HttpOnly flag in Self-Check.

= 1.3.1 - 2026-09-02 =
* Improved Malware Scanner IO.
* Improved Integrity Scanner.
* Large scans no longer stall on big files.

Older entries are in `changelog.txt`, which ships with the plugin, and the full history is published at [https://segurium.com/changelog/](https://segurium.com/changelog/).
