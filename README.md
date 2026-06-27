# pi-permissive

[![npm version](https://img.shields.io/npm/v/pi-permissive?style=for-the-badge)](https://www.npmjs.com/package/pi-permissive)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

A permissive permission gate for the [Pi coding agent](https://github.com/earendil-works/pi) — it stays out of your way, only gating what genuinely matters, and never hard-blocks anything you might legitimately want to do.

## Rules

**DENY** — hard block, never runs:

- `git push --force` to `main`
- `rm -rf` on system/home paths (`/`, `/Users`, `~/`, `$HOME`, …)
- `sudo rm`
- `mkfs`, `dd … of=/dev/…`, `shutdown`/`reboot`/`halt`/`poweroff`
- Fork bombs
- Writing/editing credentials & keys (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `.netrc`, `id_rsa`, `*.pem`, `*.key`)

**ASK** — prompts you; runs if you approve, blocks if you decline or there's no UI:

- `git push --force` (to non-main branches; `--force-with-lease` is silent)
- `git push` to `main`
- `git push --delete` (remote ref deletion)
- `git reset --hard`, `git clean -f`, `git branch -d`/`-D`, `git filter-branch`, `git reflog expire`, `git update-ref -d`
- Reading or writing `.env` files
- Reading any credential/key path

**ALLOW** — everything else, silently. This is the default.

## Install

```bash
pi install npm:pi-permissive
```

Or from GitHub:

```bash
pi install git:github.com/nilskluewer/pi-permissive
# or pin a version:
pi install git:github.com/nilskluewer/pi-permissive@v0.3.0
```

Try without installing:

```bash
pi -e git:github.com/nilskluewer/pi-permissive
```

## Tests

```bash
npm test
# or directly:
cd sandbox/permission-tests && ./run.sh
```

Requires Node 22.6+. The suite includes deterministic self-validation: every
rule carries match/no-match examples that are checked against its own regex,
so you can't change a pattern without proving what it matches.

## License

MIT
