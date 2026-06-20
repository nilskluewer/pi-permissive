/**
 * permissions.ts — a permissive permission gate for pi, with an "ask" tier.
 *
 * Philosophy
 * ----------
 * Stay out of the way of normal work. Most things are allowed silently. A
 * small set of operations is gated:
 *
 *   - DENY : hard block, cannot even be asked about. Reserved for the truly
 *            catastrophic / irreversible stuff with no legitimate use in a
 *            coding session (e.g. `mkfs`, `dd of=/dev/...`, deleting `/`,
 *            fork bombs). Deny is intentionally rare: a hard deny means the
 *            agent can never do the thing, even with the user watching.
 *
 *   - ASK  : prompt the user via `ctx.ui.confirm`. If they approve, it runs.
 *            If they decline (or there is no UI, e.g. headless mode), it is
 *            blocked. This is the tier for things that are risky but
 *            legitimate — force pushes, deleting local branches, reading
 *            `.env`, editing secrets. Putting them on ASK instead of DENY
 *            means the user can still say "yes, go ahead" instead of being
 *            permanently locked out.
 *
 *   - ALLOW: everything else, silently. This is the default and the point.
 *
 * No config file. Behaviour is encoded below so it is easy to read and edit.
 *
 * Every rule carries its own `examples` (must-match / must-not-match). The
 * `validateRules()` function in `validate.ts` checks every rule against its
 * own examples deterministically, plus rule ordering and backtracking safety.
 * This is the contract: you cannot add or change a pattern without proving,
 * in the test suite, what it matches and what it rejects.
 *
 * The decision logic lives in pure, exported functions so it can be unit
 * tested without spinning up pi. See sandbox/permission-tests/.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/** A gating verdict returned by the pure classifiers. */
export type Verdict =
  | { action: "deny"; reason: string }
  | { action: "ask"; reason: string };

/**
 * A rule. `patterns` are AND-ed (all must match). Most rules have one pattern.
 *
 * `examples` is the deterministic contract for the pattern:
 *   - match:    strings that MUST match (every pattern must match each)
 *   - noMatch:  strings that MUST NOT match (the rule as a whole must not fire)
 *
 * The validator (validate.ts) enforces these. Keep examples realistic and
 * include the tricky boundary cases — that's the whole point.
 */
export interface Rule {
  patterns: RegExp[];
  reason: string;
  action: "deny" | "ask";
  examples: { match: string[]; noMatch: string[] };
}

/** Convenience constructor for a single-pattern rule with examples. */
function rule(
  pattern: RegExp,
  reason: string,
  action: "deny" | "ask",
  examples: { match: string[]; noMatch: string[] },
): Rule {
  return { patterns: [pattern], reason, action, examples };
}

/** Convenience constructor for a multi-pattern (AND) rule with examples. */
function ruleAll(
  patterns: RegExp[],
  reason: string,
  action: "deny" | "ask",
  examples: { match: string[]; noMatch: string[] },
): Rule {
  return { patterns, reason, action, examples };
}

// ---------------------------------------------------------------------------
// Shared sub-patterns
// ---------------------------------------------------------------------------

/**
 * `git push` destination is `main` as a complete refspec token (preceded by
 * space/colon/slash, followed by whitespace or end). Avoids matching `main`
 * inside `feat-main`, `maintain`, `docs/no-push-to-main-rule`, etc.
 */
const PUSHES_TO_MAIN = /(?:\s|:|\/)main(?:\s|$)/;

/**
 * A bare force push (NOT --force-with-lease). Matches `--force` (but not
 * `--force-with-lease`) and a standalone `-f` flag.
 */
const FORCE_PUSH_BARE =
  /git\s+push\b[^;\n]*?(?:(?<![-\w])-f\b|--force(?!-with-lease))/;

const GIT_PUSH_PREFIX = /git\s+push\b[^;\n]*?/;

// ---------------------------------------------------------------------------
// BASH rules
// ---------------------------------------------------------------------------

/**
 * Bash rules, evaluated in order. First match wins, so DENY rules for a given
 * shape must come before the broader ASK rules that would also match it
 * (e.g. "force push to main" deny before "force push" ask). The validator
 * checks this ordering automatically.
 *
 * Patterns are tested against the WHOLE command string (including after `&&`
 * and `;`), so compound commands are evaluated as a unit rather than segment
 * by segment. This is what keeps everyday chained commands from prompting.
 */
export const BASH_RULES: Rule[] = [
  // --- DENY: catastrophic / irreversible, no legit coding use -------------

  rule(
    /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
    "Fork bombs are blocked.",
    "deny",
    {
      // The canonical fork bomb and a whitespace-variant.
      match: [":(){ :|:& };:", ": ( ) { : | : & } ; :"],
      // These genuinely do NOT contain the bomb sequence. Note: echoing the
      // literal bomb string DOES match (the sequence is present) — so we
      // don't list that as a noMatch.
      noMatch: ["cat fork-bomb-doc.md", "echo fork bomb notes"],
    },
  ),
  rule(/(?:^|[;&|]\s*|sudo\s+)mkfs\b/, "`mkfs` would destroy a filesystem.", "deny", {
    match: ["mkfs.ext4 /dev/sda1", "sudo mkfs /dev/sdb", "x && mkfs /dev/sda1"],
    noMatch: ["echo mkfs", "ls /sbin/mkfs-doc", "which mkfs"],
  }),
  rule(
    /\bdd\s+[^;]*of=\/dev\//,
    "`dd` to a block device would destroy a disk.",
    "deny",
    {
      match: ["dd if=img.iso of=/dev/sdb", "dd of=/dev/sda", "sudo dd if=x of=/dev/sdc"],
      noMatch: ["dd if=/dev/zero of=fill.txt bs=1 count=1", "mydd if=x of=/dev/sda", "echo dd"],
    },
  ),
  rule(
    /(?:^|[;&|]\s*|sudo\s+)(?:shutdown|reboot|halt|poweroff)\b/,
    "System power commands are blocked.",
    "deny",
    {
      match: ["shutdown -h now", "reboot", "halt", "poweroff", "sudo reboot", "foo && shutdown", "x; halt"],
      noMatch: ["echo shutdown", "cat reboot-plan.md", "grep poweroff README"],
    },
  ),

  // Recursive forced deletion of system/home root paths is unrecoverable.
  rule(
    /rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(\/|\/Users|\/home|\/etc|\/var|\/usr|\/opt|\/System|\/Library|\$HOME|~\/)/,
    "Recursive forced deletion of system/home paths is blocked.",
    "deny",
    {
      match: ["rm -rf /", "rm -rf /Users/foo", "rm -rf /home/x", "rm -rf ~/stuff", "rm -rf $HOME/x"],
      noMatch: ["rm -rf ./node_modules", "rm -rf dist/", "rm -rf ../sibling", "rm -rf ."],
    },
  ),
  rule(
    /rm\s+-[a-z]*f[a-z]*r[a-z]*\s+(\/|\/Users|\/home|\/etc|\/var|\/usr|\/opt|\/System|\/Library|\$HOME|~\/)/,
    "Recursive forced deletion of system/home paths is blocked.",
    "deny",
    {
      match: ["rm -fr /opt/thing", "rm -fr /etc/foo"],
      noMatch: ["rm -fr ./build", "rm -fr dist"],
    },
  ),
  rule(/(?:^|[;&|]\s*)sudo\s+rm\b/, "`sudo rm` is blocked.", "deny", {
    match: ["sudo rm /etc/passwd", "sudo rm -rf /var/log", "x && sudo rm /tmp/f"],
    noMatch: ["sudo apt update", "rm sudo-notes.txt", "echo sudo rm"],
  }),

  // Force pushing directly to `main` rewrites shared protected history —
  // hard deny. (Force push to other branches, and non-force push to main,
  // are ASK below.) Must come before the general force-push / main-push asks.
  ruleAll(
    [FORCE_PUSH_BARE, PUSHES_TO_MAIN],
    "Force pushing to `main` is blocked.",
    "deny",
    {
      match: [
        "git push --force origin main",
        "git push origin main --force",
        "git push -f origin main",
        "git push --force origin HEAD:main",
      ],
      noMatch: [
        "git push --force origin feat",      // force, not main -> ask
        "git push origin main",              // main, not force -> ask
        "git push --force-with-lease origin main", // force-with-lease, not bare force
      ],
    },
  ),

  // --- ASK: risky but legitimate; user can approve ------------------------

  // Bare force push to any branch (--force-with-lease stays silent/allowed).
  rule(
    FORCE_PUSH_BARE,
    "Force push rewrites remote history. Use --force-with-lease to skip this prompt.",
    "ask",
    {
      match: [
        "git push --force origin feat",
        "git push -f origin feat",
        "git push origin feat --force",
      ],
      noMatch: [
        "git push --force-with-lease origin feat",
        "git push origin feat",
      ],
    },
  ),

  // Pushing directly to the protected `main` branch (non-force).
  ruleAll(
    [GIT_PUSH_PREFIX, PUSHES_TO_MAIN],
    "Pushing directly to `main`. Prefer a feature branch + PR.",
    "ask",
    {
      match: [
        "git push origin main",
        "git push origin HEAD:main",
        "git push origin main:main",
        "git push origin refs/heads/main",
      ],
      noMatch: [
        "git push origin feat-main",            // branch name, not main
        "git push origin maintain",             // contains "main" substring
        "git push origin refs/heads/feat/main-branch",
        "git push origin main:feature",         // local main -> remote feature
      ],
    },
  ),

  // Deleting a remote branch/tag is destructive for collaborators.
  rule(
    /git\s+push\b[^;\n]*?--delete\b/,
    "Deleting a remote ref affects collaborators.",
    "ask",
    {
      match: ["git push origin --delete feat", "git push origin --delete tag v1"],
      noMatch: ["git push origin feat", "git branch -d feat"],
    },
  ),

  // History-rewriting / work-losing local git ops. Recoverable via reflog in
  // most cases, but worth a confirmation so the agent can't do them silently.
  rule(/git\s+reset\s+--hard\b/, "`git reset --hard` discards uncommitted work.", "ask", {
    match: ["git reset --hard HEAD~1", "git reset --hard origin/main"],
    noMatch: ["git reset --soft HEAD~1", "git reset HEAD~1"],
  }),
  rule(/git\s+clean\s+-[a-z]*f[a-z]*\b/, "`git clean -f` deletes untracked files permanently.", "ask", {
    match: ["git clean -fd", "git clean -fdx", "git clean -xf"],
    noMatch: ["git clean -nd", "git clean -n"],
  }),
  rule(/git\s+branch\s+-D\b/, "`git branch -D` force-deletes a local branch.", "ask", {
    match: ["git branch -D feat/x", "git branch -D main"],
    noMatch: ["git branch -d feat", "git branch --list"],
  }),
  rule(/git\s+branch\s+-d\b/, "`git branch -d` deletes a local branch.", "ask", {
    match: ["git branch -d old-branch", "git branch -d feat"],
    noMatch: ["git branch -D feat", "git branch --list", "git branch --delete feat"],
  }),
  rule(/git\s+filter-branch\b/, "`git filter-branch` rewrites history.", "ask", {
    match: ["git filter-branch -- --all", "git filter-branch HEAD"],
    noMatch: ["git log", "git rebase main"],
  }),
  rule(/git\s+reflog\s+expire\b/, "`git reflog expire` makes recovery harder.", "ask", {
    match: ["git reflog expire --expire=now --all"],
    noMatch: ["git reflog", "git reflog show"],
  }),
  rule(/git\s+update-ref\s+-d\b/, "`git update-ref -d` deletes a ref.", "ask", {
    match: ["git update-ref -d refs/heads/old"],
    noMatch: ["git update-ref refs/heads/x SHA"],
  }),
];

// ---------------------------------------------------------------------------
// PATH rules
// ---------------------------------------------------------------------------

/**
 * Real `.env` files (but not the safe `.env.example` template). Shared by
 * read (ASK) and write (ASK).
 */
const ENV_FILE = rule(
  /(^|\/)\.env(?!\.example)(?:\.|$)/,
  "`.env` file",
  "ask",
  {
    match: [".env", ".env.local", "/app/.env", "config/.env.production"],
    noMatch: [".env.example", ".env.example.local", ".env.example.production", "README.md"],
  },
);

/**
 * Credential / key locations. Used for both read and write:
 *   - WRITE/EDIT -> DENY : the agent has no business overwriting your keys.
 *   - READ       -> ASK  : the agent may legitimately need to read a secret
 *                          (e.g. debugging), but it must ask first rather
 *                          than silently slurping it into context.
 */
export const SENSITIVE_PATH_RULES: Rule[] = [
  rule(/\/\.ssh\//, "SSH directory", "deny", {
    match: ["/Users/x/.ssh/id_rsa", "/Users/x/.ssh/config", "/home/u/.ssh/config"],
    noMatch: ["./ssh-config", "/app/ssh/keys"],
  }),
  rule(/\/\.aws\//, "AWS credentials directory", "deny", {
    match: ["/Users/x/.aws/credentials", "/root/.aws/config"],
    noMatch: ["/app/aws-config"],
  }),
  rule(/\/\.gnupg\//, "GPG directory", "deny", {
    match: ["/Users/x/.gnupg/secring.gpg", "/home/u/.gnupg/pubring.gpg"],
    noMatch: ["/app/gnupg-data"],
  }),
  rule(/\/\.config\/gh\//, "GitHub CLI config", "deny", {
    match: ["/Users/x/.config/gh/hosts.yml"],
    noMatch: ["/Users/x/.config/other/gh"],
  }),
  rule(/(^|\/)\.netrc$/, "`.netrc`", "deny", {
    match: [".netrc", "/Users/x/.netrc", "/home/u/.netrc"],
    noMatch: [".netrc.example", "netrc-doc"],
  }),
  rule(/(^|\/)id_rsa($|\.pub$)/, "private SSH key", "deny", {
    match: ["id_rsa", "/Users/x/.ssh/id_rsa", "id_rsa.pub", "/home/u/.ssh/id_rsa.pub"],
    noMatch: ["readme_id_rsa_help.md", "id_rsa_doc", "my_id_rsa_backup"],
  }),
  rule(/(^|\/)id_ed25519($|\.pub$)/, "private SSH key", "deny", {
    match: ["id_ed25519", "/Users/x/.ssh/id_ed25519", "id_ed25519.pub"],
    noMatch: ["id_ed25519_doc", "readme_id_ed25519.md"],
  }),
  rule(/\.pem$/, "PEM key file", "deny", {
    match: ["/etc/ssl/private/server.pem", "cert.pem"],
    noMatch: ["cert.pem.txt", "server.peml"],
  }),
  rule(/\.key$/, "key file", "deny", {
    match: ["/secrets/ca.key", "private.key"],
    noMatch: ["key.json", "monkey.txt", ".keyboardrc"],
  }),
];

/** Write/edit rules: real `.env` is ASK, credentials/keys are DENY. */
export const WRITE_RULES: Rule[] = [
  ENV_FILE,
  // Credentials/keys: hard deny. The agent should never overwrite these.
  ...SENSITIVE_PATH_RULES,
];

/** Read rules: `.env` and all credentials are ASK. Nothing is hard-denied
 * for read — you can always approve reading a secret, you just get asked. */
export const READ_RULES: Rule[] = [
  ENV_FILE,
  ...SENSITIVE_PATH_RULES.map((r) => ({ ...r, action: "ask" as const })),
];

// ---------------------------------------------------------------------------
// Pure classifiers
// ---------------------------------------------------------------------------

function match(rules: Rule[], value: string): Verdict | undefined {
  for (const r of rules) {
    if (r.patterns.every((p) => p.test(value))) {
      return { action: r.action, reason: r.reason };
    }
  }
  return undefined;
}

/** Classify a bash command. */
export function classifyBash(command: string): Verdict | undefined {
  return match(BASH_RULES, command);
}

/** Classify a write/edit target path. */
export function classifyWrite(path: string): Verdict | undefined {
  return match(WRITE_RULES, path);
}

/** Classify a read target path. */
export function classifyRead(path: string): Verdict | undefined {
  return match(READ_RULES, path);
}

/**
 * Pure decision entry point used by tests. Mirrors what the tool_call handler
 * does, minus the pi-specific UI plumbing. Returns the verdict (deny/ask) or
 * `undefined` for allow.
 */
export function decide(
  toolName: string,
  input: { command?: string; path?: string },
): Verdict | undefined {
  if (toolName === "bash") return classifyBash(input.command ?? "");
  if (toolName === "write" || toolName === "edit") return classifyWrite(input.path ?? "");
  if (toolName === "read") return classifyRead(input.path ?? "");
  return undefined;
}

// Backwards-compatible aliases (older tests/code used these names).
export const decideBash = classifyBash;
export const decidePath = classifyWrite;

// ---------------------------------------------------------------------------
// pi extension wiring
// ---------------------------------------------------------------------------

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, ctx) => {
    const input = event.input as { command?: string; path?: string };
    const verdict = decide(event.toolName, input);
    if (!verdict) return undefined;

    // Hard deny — never runs, no prompt.
    if (verdict.action === "deny") {
      return { block: true, reason: verdict.reason };
    }

    // Ask — prompt the user. Block if declined or if there's no UI to ask
    // with (e.g. headless mode). Blocking on "no UI" keeps secrets from being
    // read silently in automated runs.
    if (!ctx.hasUI) {
      return { block: true, reason: `${verdict.reason} (no UI available to confirm)` };
    }
    const detail =
      input.command != null
        ? `${verdict.reason}\n\nCommand: ${input.command}`
        : input.path != null
          ? `${verdict.reason}\n\nPath: ${input.path}`
          : verdict.reason;
    const ok = await ctx.ui.confirm("Permission required", detail);
    if (!ok) return { block: true, reason: "Declined by user" };
    return undefined;
  });
}
