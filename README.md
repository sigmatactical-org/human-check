# sigma-human-check

[![CI](https://github.com/sigmatactical-org/human-check/actions/workflows/ci.yml/badge.svg)](https://github.com/sigmatactical-org/human-check/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.97.0-blue.svg)](https://www.rust-lang.org)

Self-hosted proof-of-work human verification for Sigma public forms, built on the OSS [ALTCHA](https://altcha.org) protocol.

- **No web framework dependencies** — only `altcha`, `serde`, and `base64`
- **No third-party API** — challenges are signed and verified locally
- **Privacy-friendly** — no cookies, fingerprinting, or external CAPTCHA vendor

Used by **identity** (`POST /register`) and **contact** (`POST /contact`).

## Configuration

| Variable | Purpose |
| --- | --- |
| `HUMAN_CHECK_DISABLED` | Set `true` to skip verification (local dev only) |
| `HUMAN_CHECK_HMAC_SECRET` | HMAC signing secret (≥32 characters) |
| `HUMAN_CHECK_KEY_SECRET` | Key signature secret (≥32 characters) |
| `HUMAN_CHECK_COST` | PoW difficulty (default `5000`) |
| `HUMAN_CHECK_TTL_SECS` | Challenge lifetime in seconds (default `600`) |

`HumanCheck::from_env` recognises exactly two valid setups and **fails closed** on anything else: with both secrets set it enables verification, and with `HUMAN_CHECK_DISABLED=true` it skips verification and logs a warning. A missing or too-short secret is an error that must stop the service from starting, because a public form that quietly accepts unverified submissions looks healthy right up until the spam arrives.

## Integration notes

1. Call [`HumanCheck::from_env`](src/human_check.rs) once at startup and propagate its error out of `main`.
2. Expose `GET /human-check/challenge` returning JSON from [`HumanCheck::issue_challenge`](src/human_check.rs).
3. Include the ALTCHA widget on the form (`theme/assets/templates/widgets/human_check.html`).
4. On `POST`, verify the `altcha` form field with [`HumanCheck::verify_payload`](src/human_check.rs) before side effects, turning an error into visitor-facing wording with [`rejection_message`](src/lib.rs).

## Brand & artwork

© Sigma Tactical Group. **All rights reserved.**

The Sigma Tactical Group name, logos, marks, artwork, and visual identity are **proprietary**. They are not covered by this repository's source-code license. See [BRANDING.md](BRANDING.md).

## License

MIT OR Apache-2.0
