=== Segurium – Malware Removal & Cleanup, Firewall, Two-Factor Authentication ===
Contributors: segurium
Tags: malware-removal, hacked, malware-scanner, two-factor-authentication, firewall
Requires at least: 6.2
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0.2
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Site hacked? Free WordPress malware removal: scan, clean infected files, restore them. Plus firewall, brute-force protection, 2FA, geo-blocking.

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
* **Auto-cleanup on detection** — When real-time scanning flags a file, Segurium can clean it without waiting for an admin to open the dashboard.
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
* **Migration importer** — Import your existing settings from Wordfence, All-In-One Security and Solid Security so you don't lose your hardening when you switch. Sucuri Security is detected too, but its settings live in Sucuri's cloud dashboard and cannot be read locally, so there is nothing to import.
* **Disaster recovery** — Local encrypted backups can be extracted with a tiny PHP one-liner, even if Segurium is uninstalled.
* **Embedded support**.

= How the Pro service tier differs =

Cleanups are performed by Segurium's cloud service and counted against a per-installation quota. The Free service tier covers up to **3 cleanups per rolling 30 days** — enough for an occasional incident on a typical site. The Pro service tier raises that quota for sites that need higher volume (recurring infections, hosts under sustained attack, sites with high reliability requirements). The plugin code, the detection engines, and every feature listed above are identical on both tiers; the only difference is the quota ceiling enforced server-side.

= Privacy by default =

* **Scanning is opt-in.** Until you explicitly accept the service disclosure on the plugin's admin page, Segurium doesn't contact the cloud and stays idle.
* **Hash-first, body-on-miss.** During a scan, files are checked by SHA-256 first. Only files whose hash is unknown to the cloud have their bytes uploaded for classification, so the volume of content actually leaving your server is small and bounded by what's new on disk.
* **No telemetry on your visitors.** Segurium looks at files and security incidents, not at the people who visit your site.
* **On-premise mode.** Switch off cloud-assisted malware detection and scans send hashes, paths and metadata only.

= Designed to stay lean =

Segurium ships as a PHP plugin with no bundled binaries, no vendored third-party scanners, and no hidden background daemons. The heavy lifting — classification, signature curation, integrity manifests — lives in our cloud service, so your WordPress install stays fast and your hosting bill stays flat.

== Installation ==

1. Upload the `segurium` folder to `/wp-content/plugins/`, or install through **Plugins → Add New** in the WordPress admin.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Open **Segurium** in the admin sidebar and accept the service disclosure to enable scanning.
4. (Optional) Import settings from your previous security plugin via **Segurium → Migration**.
5. (Optional) Enable two-factor authentication, geo-blocking and security headers from their respective tabs.

== Frequently Asked Questions ==

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

= Google flagged my site or my host suspended it. Can Segurium help? =

Segurium removes the malware that triggered the flag. After the cleanup, run a fresh scan to confirm the site is clean, then ask Google Search Console or your host for a review. Segurium does not file that review request for you; it removes the reason for it.

= Will Segurium slow my site down? =

It shouldn't. Scans run in chunked background jobs, behind a lock so a single run can't pile on top of itself. Real-time scanning only inspects new and modified files. The plugin keeps no large tables in memory and ships no bundled binaries.

= What happens if Segurium flags a file that isn't really malware? =

Every cleanup is reversible. Originals are encrypted (AES-256-GCM) and stored locally — retained for up to 30 days, subject to per-bucket count and size caps — and you can restore from backup in one click. You can also submit a **false-positive report** directly from the threats list, and our team uses those to improve classification.

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

Cloud Threat Inspection, our own service at `cti.segurium.com`, provides malware verdicts, integrity manifests, geo-location data, trusted-proxy IP ranges, support intake, cleanup files, and a per-installation cleanup quota that gates how many files the cloud will clean in a rolling 30-day window. The service is contacted when:

* You accept the service disclosure on the plugin's admin page (a one-time **installation registration** request is sent: a random commitment hash, your site name, your site URL, your WordPress version, and — if you enabled email alerts — the alert email address you entered).
* A malware, integrity, real-time or upload scan is running.
* You request cleanup of a specific infected file (the cleaned bytes are fetched from the cloud by hash; only the SHA-256 of the file you selected is sent in that request).
* The scheduled GeoIP database update runs (daily).
* The scheduled trusted-proxies update runs (daily).
* The scheduled component-inventory ping runs (daily; sends the list of installed plugin/theme slugs and versions and your WordPress version, so we can spot tampered, delisted or abandoned components).
* You submit a support request, false-positive report or missed-malware report from the plugin's admin pages (the data you typed, plus the file bytes you attached, are sent).
* You change a settings group (a settings snapshot of that area is sent so the cloud side stays in sync).
* A brute-force lockout, geo-block or other security event fires (a small JSON payload with the event type, your site URL, your domain, your WordPress / PHP / plugin versions, and a SHA-256 hash of the username — never the username itself or the password — is sent).
* You activate or deactivate the plugin (a one-line `plugin_activated` / `plugin_deactivated` ping is sent so the cloud side knows the install is no longer reachable; the deactivation ping is skipped entirely if you never accepted the service disclosure).

**Data sent during scans:** SHA-256 hashes of files on your server, file paths relative to your WordPress installation, file sizes, file modification times, plugin and theme version strings, and your WordPress version. **For files whose SHA-256 is not yet known to the cloud verdict database, the file's bytes are also uploaded so the file can be classified.** This applies to malware scans and to real-time / upload scanning.

**Turning the upload off:** the "Cloud-assisted malware detection" setting on the Settings tab controls it. Switch it off for On-premise mode and scans send hashes, paths and metadata only. A file whose hash the cloud does not recognise then stays unresolved, because the plugin will not upload it to find out what it is. Two uploads stay available in that mode, since you pick the file yourself each time: a false-positive report and a support-ticket attachment.

**Retention:** file samples uploaded for analysis are kept for up to 365 days and then removed by an automated nightly purge. The full schedule is in the privacy policy linked below.

Each request from your installation is identified by a random installation identifier (IID) issued at registration time; we do not store or send any WordPress user data, content, or visitor information. The privacy policy linked below names the data controller and how to reach them.

* Terms of Service: [https://segurium.com/terms](https://segurium.com/terms)
* Privacy Policy: [https://segurium.com/privacy](https://segurium.com/privacy)

= Freemius (api.freemius.com, checkout.freemius.com, wp.freemius.com) =

Segurium uses the Freemius WordPress SDK (bundled in `freemius/`) to handle license activation, paid-plan checkout, and account management for the Pro plan. The SDK ships in **anonymous mode**: on activation Segurium tells the SDK to skip the connect prompt, so no request is sent to Freemius and no telemetry is collected from your install.

Freemius servers are contacted only when:

* You explicitly click an upgrade or "Manage billing" button in the Segurium account page and complete the checkout on `checkout.freemius.com`.
* You activate, sync or deactivate a Pro license through the account page (the SDK posts the licence key, your site URL, your WordPress / PHP versions, and the plugin version to `api.freemius.com`).

If you never visit the account page or never enter a licence, no request is ever made to Freemius from your site.

Freemius is operated by Freemius, Inc.

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

Segurium ships the Freemius WordPress SDK in `freemius/` for licensing, checkout and support flows. A small number of files inside that SDK (`freemius/assets/js/jquery.form.js` and `freemius/assets/js/postmessage.js`) are minified upstream and shipped as-is. The unminified source for the entire SDK is published under GPL-3.0 at:

* https://github.com/Freemius/wordpress-sdk

The SDK version bundled with this release is recorded in `freemius/start.php` (`$this_sdk_version`).

== Screenshots ==

1. Security Self-Check — A+ to F grade across hardening, malware, info disclosure, cookies, and HTTP headers. The hero view.
2. Malware scan — clean state. SHA-256 hash check across every file with the cloud verdict database, plus full scanned-file count.
3. Integrity scan — per-component status (core, plugins, themes), file counts, and Fix / Restore actions for files that drifted from the official source.
4. Geo-blocking — preset regions (EU / Americas / Asia-Pacific / Africa / Middle East / High-Risk) plus per-country control, configurable block action.
5. Firewall — IPv4/IPv6/CIDR allow- and block-lists, with auto-detected CDN and reverse-proxy ranges so true visitor IPs are honoured.
6. Brute-force protection — recommended-vs-custom presets, lockout windows, extended bans, XML-RPC protection, and live attack statistics.
7. Two-Factor Authentication — TOTP authenticator app and email verification, per-role enforcement, grace period, and trusted-device duration.
8. Security headers — HSTS, CSP, Permissions-Policy, Referrer-Policy, cookie hardening with a live preview of the headers Segurium will send.
9. Information Shield — strips WordPress version, REST API discovery links, RSD/WLW pingback, generator tag, and other version-leaking metadata.
10. Migration tool — detects existing security plugins (Wordfence / All-In-One Security / Sucuri / Solid Security) and previews their settings before import.
11. Scheduled scans + alerts — cron-driven daily/weekly/monthly scans with email notifications and automatic clean of high-confidence detections.
12. Free vs Pro plan comparison — every hardening feature ships in the free tier; Pro unlocks unlimited cleanup quota and reversible-backup recovery.

== Changelog ==

= 1.0.2 - 2026-08-10 =
* Language translation fixes.
* On-premise mode now stops file uploads.
* Consent screen shows accurate retention period.

= 1.0.1 - 2026-08-08 =
* Brute-force lockout covers XML-RPC logins.
* Brute-force lockout covers 2FA login step.
* Translations updated.

= 1.0.0 - 2026-07-19 =
* Fixes integrity scans stalling on large sites
* Major version bump

= 0.1.8 - 2026-07-07 =
* Fixes anonymous access to scan endpoints.
* Improves compatibility with hosts that disable shell access.

= 0.1.7 - 2026-06-24 =
* Maintenance release.

= 0.1.6 - 2026-06-16 =
* minor fixes

= 0.1.5 - 2026-06-04 =
* Scans now handle sites with millions of files.
* Real-time file monitoring works reliably on large sites.
* Temporary network errors no longer ruin a scan batch.
* Scan progress no longer stalls on long scans.
* Completed scans show the correct duration.
* Hardened protection against unauthorized admin actions.
* Translations updated for 13 languages.

= 0.1.4 - 2026-05-30 =
* Large scans now resume after timeouts instead of aborting.
* Scans complete reliably without hanging on pending results.
* Cleanup limit notice now shows the next available date.
* Scans no longer start before the plugin is fully activated.
* Firewall no longer disables itself unexpectedly.

= 0.1.3 - 2026-05-24 =
* Faster malware scans.
* Progress bar shows percentage label.
* Scan summary lists failed and skipped files.
* Cleanup quota counter shows correct numbers.
* Checkout pre-fills name and email.
* Works again on WordPress 6.0.
* Security Headers presets no longer fight custom toggles.
* X-XSS-Protection options include inline guidance.
* Self-Check runs automatically on first open.
* Self-Check runs once a day.
* Integrity Restore shows clearer errors.
* Admin tabs use shareable URLs.
* Stop button hides the scan progress bar.
* Scan counters no longer jump backwards.
* Duplicate files no longer break scan totals.
* Geo block page renders without admin notice noise.
* Geo database freshness updates on every check.

= 0.1.2 - 2026-05-08 =
* Minor UI improvements
* Cleaned files clear from malware list after rescan.
* Fixes admin lockout from geo settings revert.
* Two-factor settings appear on user profile page.
* Scans no longer hang behind web firewalls.
* Scans recover faster from stalled workers.
* Stop scan no longer crashes the worker.

= 0.1.1 - 2026-05-06 =
* Add 13 new translations.
* Admin pages follow the WordPress admin color scheme.
* Lower background traffic on idle admin tabs.
* Faster admin page loads.
* Warn before rotating older backups.
* Keep 2FA Save button visible when disabled.
* Recovery banner for moved or cloned sites.

= 0.1.0 =
* Initial release.
