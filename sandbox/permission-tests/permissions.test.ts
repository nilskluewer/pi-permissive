/**
 * Permission system test suite.
 *
 * Run with:
 *   node --test --experimental-strip-types permissions.test.ts
 *
 * (Node 22.6+ strips types natively. Node 26 does this by default.)
 *
 * Tests cover three buckets for bash and paths:
 *   - DENY : must be blocked
 *   - ALLOW: must pass silently (the permissive default)
 *   - ASK  : n/a for this extension — there is no "ask" tier, so we only
 *            assert these are NOT blocked. (Listed for completeness so the
 *            intent of borderline commands is documented.)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { decide, decideBash, decidePath } from "../../extensions/permissions.ts";

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

function denied(tool: string, input: object) {
  const d = decide(tool, input);
  assert.ok(d?.block, `expected DENY but got ALLOW for ${tool} ${JSON.stringify(input)}`);
}

function allowed(tool: string, input: object) {
  const d = decide(tool, input);
  assert.equal(d, undefined, `expected ALLOW but got ${JSON.stringify(d)} for ${tool} ${JSON.stringify(input)}`);
}

// --------------------------------------------------------------------------
// bash — must DENY
// --------------------------------------------------------------------------

const BASH_DENY: string[] = [
  "git push --force origin main",
  "git push origin main --force",
  "git push -f origin feat",
  "git push origin main",
  "git push origin main:main",
  "git push origin HEAD:main",
  "git push origin refs/heads/main",
  "git reset --hard origin/main",
  "git clean -fd",
  "git clean -fdx",
  "git branch -D feat/x",
  "git filter-branch -- --all",
  "git reflog expire --expire=now --all",
  "git update-ref -d refs/heads/old",
  "rm -rf /",
  "rm -rf /Users/foo",
  "rm -rf /home/x",
  "rm -rf ~/stuff",
  "rm -rf $HOME/stuff",
  "rm -fr /opt/thing",
  "sudo rm /etc/passwd",
  "mkfs.ext4 /dev/sda1",
  "dd if=img.iso of=/dev/sdb",
  "shutdown -h now",
  "reboot",
  ":(){ :|:& };:",
];

test("bash: destructive commands are DENIED", () => {
  for (const cmd of BASH_DENY) denied("bash", { command: cmd });
});

// --------------------------------------------------------------------------
// bash — must ALLOW (permissive default; no prompt)
// --------------------------------------------------------------------------

const BASH_ALLOW: string[] = [
  // everyday chained commands (the original pain point)
  "cd /Users/nilskluewer/GitCodex/website-nilskluewer-dev && git checkout -b feat && git add -A && git commit -m x",
  "echo '--- follow redirect ---'; curl -sIL https://nilskluewer.dev/google17960a29cf544530.html | grep -iE 'HTTP|location'",
  "git push origin feat/improve-ui",
  "git push -u origin docs/no-push-to-main-rule",
  "git push origin feat-main",
  "git push origin maintain",
  "git push origin refs/heads/feat/main-branch",
  // force-with-lease is allowed (safer)
  "git push --force-with-lease origin feat",
  // normal git ops
  "git reset --soft HEAD~1",
  "git reset HEAD~1",
  "git checkout main",
  "git branch -d old-branch",
  "git stash",
  "git push origin feature",
  // rm that is NOT recursive-forced on system paths
  "rm file.txt",
  "rm -f ./build/tmp.log",
  "rm -rf ./node_modules",
  "rm -rf dist/",
  "rm -rf ./website-nilskluewer-dev",
  // common tooling
  "npm install",
  "open index.html",
  "ls -la",
  "grep -rn foo . --include='*.html'",
  "curl https://nilskluewer.dev/robots.txt",
  "cd ~ && pwd",
  // dd not targeting a block device
  "dd if=/dev/zero of=fill.txt bs=1 count=1",
];

test("bash: normal / chained commands are ALLOWED", () => {
  for (const cmd of BASH_ALLOW) allowed("bash", { command: cmd });
});

// Compound edge case: a DENY buried inside a `&&` chain must still be caught,
// because we match the whole string. Build a few composed commands.
test("bash: deny rule fires even when buried in a compound command", () => {
  denied("bash", { command: "cd repo && git add -A && git push origin main" });
  denied("bash", { command: "echo hi; git reset --hard HEAD~1; echo bye" });
  denied("bash", { command: "git commit -m x && git push --force origin main" });
});

// --------------------------------------------------------------------------
// bash — borderline commands documented as NOT blocked (the "ask" tier we
// intentionally collapsed to allow). Asserting ALLOW so the choice is explicit.
// --------------------------------------------------------------------------

test("bash: borderline commands are ALLOWED by design (documented)", () => {
  const borderline = [
    "rm -rf .",                          // cwd-relative; not a system path
    "rm -rf ../sibling",                 // relative, not under a protected root
    "git push origin main:feature",      // pushes local main to remote feature (not to main)
    "git checkout -- file.txt",          // discards local changes
    "git restore file.txt",
    "git stash drop",                    // loses a stash
  ];
  for (const cmd of borderline) allowed("bash", { command: cmd });
});

// --------------------------------------------------------------------------
// paths — must DENY (write / edit)
// --------------------------------------------------------------------------

const PATH_DENY: string[] = [
  ".env",
  ".env.local",
  "/app/.env",
  "/Users/x/.ssh/id_rsa",
  "/Users/x/.ssh/config",
  "/Users/x/.aws/credentials",
  "/Users/x/.gnupg/secring.gpg",
  "/Users/x/.config/gh/hosts.yml",
  "/Users/x/.netrc",
  "id_rsa",
  "/home/x/.ssh/id_ed25519",
  "/etc/ssl/private/server.pem",
  "/secrets/ca.key",
];

test("paths: sensitive paths are DENIED for write/edit", () => {
  for (const path of PATH_DENY) {
    denied("write", { path });
    denied("edit", { path });
  }
});

// --------------------------------------------------------------------------
// paths — must ALLOW
// --------------------------------------------------------------------------

const PATH_ALLOW: string[] = [
  "index.html",
  "/Users/nilskluewer/GitCodex/website-nilskluewer-dev/styles.css",
  "~/GitCodex/repo/script.js",
  "src/index.ts",
  "AGENTS.md",
  ".env.example",          // examples are fine (not a real secret)
  "docs/setup.md",
  "/tmp/build.log",
];

test("paths: normal files are ALLOWED for write/edit", () => {
  for (const path of PATH_ALLOW) {
    allowed("write", { path });
    allowed("edit", { path });
  }
});

// --------------------------------------------------------------------------
// tool routing
// --------------------------------------------------------------------------

test("read is always allowed, even on sensitive paths", () => {
  allowed("read", { path: "/Users/x/.ssh/id_rsa" });
  allowed("read", { path: ".env" });
});

test("unknown tools are allowed (passthrough)", () => {
  allowed("mcp_foo", { command: "rm -rf /" });
});

test("decideBash / decidePath work standalone", () => {
  assert.ok(decideBash("git push origin main")?.block);
  assert.equal(decideBash("ls"), undefined);
  assert.ok(decidePath(".env")?.block);
  assert.equal(decidePath("index.html"), undefined);
});

test("empty / undefined inputs do not throw", () => {
  allowed("bash", {});
  allowed("write", {});
  allowed("edit", {});
  allowed("bash", { command: "" });
});
