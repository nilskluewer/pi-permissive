# pi-permissions

A deliberately **permissive** permission gate for the [pi coding agent](https://github.com/earendil-works/pi).

Most permission systems prompt constantly and get in the way. This one stays
out of the way: it **only blocks commands that are genuinely destructive**, and
lets everything else through silently — no prompts, no friction.

## What it blocks

**Bash** (evaluated against the *whole* command string, including after `&&`
and `;`, so chained commands never prompt):

- Force push (`git push --force` / `-f`) — `--force-with-lease` is allowed
- Pushing directly to `main` (your protected branch)
- `git reset --hard`, `git clean -f`, `git branch -D`, `git filter-branch`,
  `git reflog expire`, `git update-ref -d`
- `rm -rf` on system/home paths (`/`, `/Users`, `/home`, `/etc`, `~/`, `$HOME`, …)
- `sudo rm`
- `mkfs`, `dd … of=/dev/…`, `shutdown`/`reboot`/`halt`/`poweroff`
- Fork bombs

**Write / edit** paths:

- `.env` (but not `.env.example`)
- `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `.netrc`
- Private keys (`id_rsa`, `id_ed25519`, `*.pem`, `*.key`)

**Read** is always allowed. Unknown tools pass through.

## What it does NOT do

- No config file. Behaviour is encoded directly in `extensions/permissions.ts`
  so it's easy to read and edit.
- No "ask" tier. If a command isn't on the deny list, it runs. This is the
  whole point — to stop the constant permission prompts.

## Install

```bash
pi install git:github.com/nilskluewer/pi-permissions
# or pin a version/tag:
pi install git:github.com/nilskluewer/pi-permissions@v0.1.0
```

## Tests

The decision logic is split into pure, exported functions
(`decideBash`, `decidePath`, `decide`) so it can be unit-tested without
spinning up pi.

```bash
cd sandbox/permission-tests
./run.sh            # or: node --test --experimental-strip-types permissions.test.ts
```

Requires Node 22.6+ for native TypeScript type stripping.

## License

MIT
