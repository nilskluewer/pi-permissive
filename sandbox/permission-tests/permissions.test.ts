/**
 * Permission system test suite.
 *
 * Run with:
 *   node --test --experimental-strip-types permissions.test.ts
 *
 * (Node 22.6+ strips types natively. Node 26 does this by default.)
 *
 * Tests cover three tiers for bash and paths:
 *   - DENY : must return { action: "deny" }  (hard block, no prompt)
 *   - ASK  : must return { action: "ask" }   (prompt the user)
 *   - ALLOW: must return undefined           (silent pass-through)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  decide,
  classifyBash,
  classifyWrite,
  classifyRead,
} from "../../extensions/permissions.ts";

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

function expectVerdict(
  tier: "deny" | "ask",
  tool: string,
  input: object,
) {
  const v = decide(tool, input);
  assert.ok(
    v && v.action === tier,
    `expected ${tier.toUpperCase()} but got ${JSON.stringify(v)} for ${tool} ${JSON.stringify(input)}`,
  );
}

const denied = (tool: string, input: object) => expectVerdict("deny", tool, input);
const asked = (tool: string, input: object) => expectVerdict("ask", tool, input);

function allowed(tool: string, input: object) {
  const v = decide(tool, input);
  assert.equal(
    v,
    undefined,
    `expected ALLOW but got ${JSON.stringify(v)} for ${tool} ${JSON.stringify(input)}`,
  );
}

// --------------------------------------------------------------------------
// bash — DENY (catastrophic / irreversible)
// --------------------------------------------------------------------------

const BASH_DENY: string[] = [
  // force push to main (worst case — rewrites shared protected history)
  "git push --force origin main",
  "git push origin main --force",
  "git push -f origin main",
  "git push --force origin HEAD:main",
  // catastrophic filesystem / system
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

test("bash: catastrophic commands are DENIED", () => {
  for (const cmd of BASH_DENY) denied("bash", { command: cmd });
});

// --------------------------------------------------------------------------
// bash — ASK (risky but legitimate; user can approve)
// --------------------------------------------------------------------------

const BASH_ASK: string[] = [
  // force push to a non-main branch (force-with-lease stays silent/allowed)
  "git push --force origin feat",
  "git push -f origin feat",
  "git push origin feat --force",
  // pushing directly to main (non-force)
  "git push origin main",
  "git push origin HEAD:main",
  "git push origin main:main",
  "git push origin refs/heads/main",
  // deleting remote refs
  "git push origin --delete feat",
  // local history/work ops
  "git reset --hard origin/main",
  "git clean -fd",
  "git clean -fdx",
  "git branch -D feat/x",
  "git branch -d old-branch",   // pruning local branches -> ASK, not deny
  "git filter-branch -- --all",
  "git reflog expire --expire=now --all",
  "git update-ref -d refs/heads/old",
];

test("bash: risky-but-legitimate commands are ASKED", () => {
  for (const cmd of BASH_ASK) asked("bash", { command: cmd });
});

// --------------------------------------------------------------------------
// bash — ALLOW (permissive default; no prompt)
// --------------------------------------------------------------------------

const BASH_ALLOW: string[] = [
  // everyday chained commands (the original pain point)
  "cd /Users/nilskluewer/GitCodex/website-nilskluewer-dev && git checkout -b feat && git add -A && git commit -m x",
  "echo '--- follow redirect ---'; curl -sIL https://nilskluewer.dev/google17960a29cf544530.html | grep -iE 'HTTP|location'",
  "git push origin feat/improve-ui",
  "git push -u origin docs/no-push-to-main-rule",
  "git push origin feat-main",       // branch name contains "main" but isn't main
  "git push origin maintain",
  "git push origin refs/heads/feat/main-branch",
  // force-with-lease is allowed silently (safer)
  "git push --force-with-lease origin feat",
  // normal git ops
  "git reset --soft HEAD~1",
  "git reset HEAD~1",
  "git checkout main",
  "git stash",
  "git push origin feature",
  "git push origin main:feature",     // local main -> remote feature (not to main)
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

// Compound edge cases: a rule must fire even when buried in a `&&` / `;` chain.
test("bash: rules fire even when buried in a compound command", () => {
  denied("bash", { command: "cd repo && git add -A && git push --force origin main" });
  asked("bash", { command: "cd repo && git add -A && git push origin main" });
  asked("bash", { command: "echo hi; git reset --hard HEAD~1; echo bye" });
  asked("bash", { command: "git commit -m x && git branch -D feat/x" });
});

test("bash: borderline commands are ALLOWED by design (documented)", () => {
  const borderline = [
    "rm -rf .",                          // cwd-relative; not a system path
    "rm -rf ../sibling",                 // relative, not under a protected root
    "git checkout -- file.txt",          // discards local changes
    "git restore file.txt",
    "git stash drop",                    // loses a stash (not gated)
    "git commit --amend",                // local history, common
    "git rebase main",                   // local, common
  ];
  for (const cmd of borderline) allowed("bash", { command: cmd });
});

// --------------------------------------------------------------------------
// write / edit — DENY (credentials / keys; agent must never overwrite)
// --------------------------------------------------------------------------

const WRITE_DENY: string[] = [
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

test("write/edit: credential & key paths are DENIED", () => {
  for (const path of WRITE_DENY) {
    denied("write", { path });
    denied("edit", { path });
  }
});

// --------------------------------------------------------------------------
// write / edit — ASK (.env)
// --------------------------------------------------------------------------

const WRITE_ASK: string[] = [".env", ".env.local", "/app/.env"];

test("write/edit: real .env files are ASKED", () => {
  for (const path of WRITE_ASK) {
    asked("write", { path });
    asked("edit", { path });
  }
});

// --------------------------------------------------------------------------
// write / edit — ALLOW
// --------------------------------------------------------------------------

const WRITE_ALLOW: string[] = [
  "index.html",
  "/Users/nilskluewer/GitCodex/website-nilskluewer-dev/styles.css",
  "~/GitCodex/repo/script.js",
  "src/index.ts",
  "AGENTS.md",
  ".env.example",          // template, not a real secret
  "docs/setup.md",
  "/tmp/build.log",
];

test("write/edit: normal files are ALLOWED", () => {
  for (const path of WRITE_ALLOW) {
    allowed("write", { path });
    allowed("edit", { path });
  }
});

// --------------------------------------------------------------------------
// read — secrets are ASK (not silent), nothing is hard-denied for read
// --------------------------------------------------------------------------

test("read: secrets & .env are ASKED (never silently read)", () => {
  const secret = [
    ".env",
    ".env.local",
    "/app/.env",
    "/Users/x/.ssh/id_rsa",
    "/Users/x/.aws/credentials",
    "/Users/x/.gnupg/secring.gpg",
    "/Users/x/.config/gh/hosts.yml",
    "/Users/x/.netrc",
    "id_rsa",
    "/home/x/.ssh/id_ed25519",
    "/etc/ssl/private/server.pem",
    "/secrets/ca.key",
  ];
  for (const path of secret) asked("read", { path });
});

test("read: normal files are ALLOWED", () => {
  for (const path of WRITE_ALLOW) allowed("read", { path });
});

test("read: .env.example is ALLOWED (not a real secret)", () => {
  allowed("read", { path: ".env.example" });
});

// --------------------------------------------------------------------------
// tool routing & standalone classifiers
// --------------------------------------------------------------------------

test("unknown tools are allowed (passthrough)", () => {
  allowed("mcp_foo", { command: "rm -rf /" });
});

test("classifiers work standalone", () => {
  assert.equal(classifyBash("git push --force origin main")?.action, "deny");
  assert.equal(classifyBash("git push origin main")?.action, "ask");
  assert.equal(classifyBash("ls"), undefined);
  assert.equal(classifyWrite("/Users/x/.ssh/id_rsa")?.action, "deny");
  assert.equal(classifyWrite(".env")?.action, "ask");
  assert.equal(classifyWrite("index.html"), undefined);
  assert.equal(classifyRead(".env")?.action, "ask");
  assert.equal(classifyRead("index.html"), undefined);
});

test("empty / undefined inputs do not throw", () => {
  allowed("bash", {});
  allowed("write", {});
  allowed("edit", {});
  allowed("read", {});
  allowed("bash", { command: "" });
});
