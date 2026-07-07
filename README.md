# Segurium

Website hacked? Free malware removal and antivirus scan for WordPress: clean
infected files, restore them. Firewall, brute force, 2FA included.

**Install it from the WordPress plugin directory:**
[wordpress.org/plugins/segurium](https://wordpress.org/plugins/segurium/)

---

## This repository is a mirror

The plugin is developed elsewhere and published to WordPress.org. This
repository carries the released code so you can read it, diff it, and cite
it. Each tag holds the released tree of that version exactly as WordPress.org
serves it, plus the three files this repository adds: `README.md`,
`SECURITY.md` and `LICENSE`.

Install from WordPress.org, not from a clone. A clone gets no updates and
no signature checks.

## What it does

Most security plugins scan the site, name the infected files, then ask for
money to clean them. Segurium does the cleanup. It finds the infected files,
strips the malicious code, and puts the original file back, keeping a
reversible encrypted backup. The free tier covers up to 3 cloud cleanups per
rolling 30 days, which is enough for a typical incident.

If Google flagged your site, your host suspended the account, or visitors get
redirected to a spam page, that is the job this plugin was built for.

Every feature below ships on every install, free and paid alike. Only the
cleanup quota differs.

- **Malware removal.** A full filesystem scan finds the infected files. One
  click strips the malicious code and keeps an encrypted, reversible backup.
- **Bulk remediation.** Queue every detected threat for cleanup in one click.
- **Auto-cleanup on detection.** Real-time scanning can clean a flagged file
  without waiting for an admin to open the dashboard.
- **Real-time and upload scanning.** New and modified files get checked
  automatically. Infected uploads are blocked before they land on disk.
- **Integrity scan.** Verify WordPress core, plugins and themes against
  upstream manifests, and restore a rewritten file to its official content.
- **Encrypted reversible backups.** Originals are stored locally with
  AES-256-GCM before anything is cleaned. Restore is one click.
- **Scheduled scans.** Off, daily or weekly, with a locale-aware time picker.
- **Two-factor authentication.** TOTP apps, email fallback, backup codes,
  trusted devices, per-role enforcement.
- **Brute-force protection.** Tiered lockouts on wp-login.php and XML-RPC,
  honeypot field, manual IP unlock, optional hCaptcha.
- **Firewall.** Allow and deny rules by IP, CIDR range and country.
- **Geo-blocking.** Country filtering from a local binary database, with a
  confirm-or-revert safety net so you cannot lock yourself out.
- **Security headers.** Response headers, cookie hardening, five preset modes.
- **Information Shield.** Hides version fingerprints, discovery endpoints and
  asset version strings.
- **Self-Check grade.** Checks roll up into an A+ to F grade with one-click
  fixes.
- **Migration importer.** Imports settings from Wordfence, All-In-One
  Security and Solid Security.

## Requirements

WordPress 6.2 or newer, PHP 7.4 or newer.

## Privacy

Scanning is opt-in. Segurium contacts nothing until you accept the service
disclosure on the plugin's admin page.

During a scan, files are checked by SHA-256 first. Only files whose hash is
unknown to the cloud have their bytes uploaded for classification. Switch off
cloud-assisted detection for on-premise mode, and scans send hashes, paths and
metadata only.

Segurium looks at files and security incidents. It collects nothing about the
people who visit your site.

The full disclosure of every external service, the data each one receives, and
when, is in the [plugin readme](readme.txt) under "External Services".
See also the [privacy policy](https://segurium.com/privacy/).

## Reporting a security issue

Read [SECURITY.md](SECURITY.md). Never open a public issue for a
vulnerability.

## Support and bug reports

Support questions go to the
[WordPress.org support forum](https://wordpress.org/support/plugin/segurium/),
where the whole team reads them.

Bug reports about the released code are welcome in this repository's issues.
Pull requests are not accepted here: this is a mirror, so a merge would be
overwritten by the next release push.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
