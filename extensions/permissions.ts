/**
 * permissions.ts — a deliberately permissive permission gate for pi.
 *
 * Goal: stay out of the way of normal work. Only block commands that are
 * genuinely destructive or that violate hard project rules (e.g. pushing to
 * `main`). Everything else is allowed silently, with no prompts.
 *
 * No config file. Behaviour is encoded below so it is easy to read and edit.
 *
 * The decision logic lives in pure, exported functions so it can be unit
 * tested without spinning up pi. See sandbox/permission-tests/.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export interface Decision {
  block: true;
  reason: string;
}

interface Rule {
  pattern: RegExp;
  reason: string;
}

/**
 * Bash commands that are always blocked. Keep this list short and obvious.
 * Anything not listed here is allowed without prompting.
 *
 * Patterns are tested against the WHOLE command string (including after `&&`
 * and `;`), so compound commands are evaluated as a unit rather than segment
 * by segment. This is what keeps everyday chained commands from prompting.
 */
export const DENIED_BASH: Rule[] = [
  // Force pushing (force-with-lease is allowed, it is safer).
  {
    pattern: /git\s+push\s+(?:[^;\n]*\s)?--force(?:\s|$|[^-])/,
    reason: "Force push is blocked. Use --force-with-lease instead.",
  },
  {
    pattern: /git\s+push\s+(?:[^;\n]*\s)?-f\b/,
    reason: "Force push (-f) is blocked. Use --force-with-lease instead.",
  },

  // Never push directly to the protected main branch. We block when the
  // DESTINATION of the refspec is `main` (e.g. `main`, `HEAD:main`,
  // `feat:main`, `refs/heads/main`), but allow `main:feature` (local main
  // pushed to a remote feature branch).
  {
    // `main` must be a complete refspec destination token: preceded by a
    // space, colon, or slash, and followed by whitespace or end. This avoids
    // matching `main` inside hyphenated branch names like
    // `docs/no-push-to-main-rule` or `feat-main`, while still catching
    // `main`, `HEAD:main`, `feat:main`, and `refs/heads/main`.
    pattern: /git\s+push\b[^;\n]*?(?:\s|:|\/)main(?:\s|$)/,
    reason: "Pushing directly to `main` is blocked. Use a feature branch + PR.",
  },

  // History-rewriting / destructive git operations.
  { pattern: /git\s+reset\s+--hard\b/, reason: "`git reset --hard` is blocked." },
  { pattern: /git\s+clean\s+-[a-z]*f[a-z]*\b/, reason: "`git clean -f` is blocked." },
  { pattern: /git\s+branch\s+-D\b/, reason: "`git branch -D` (force delete) is blocked." },
  { pattern: /git\s+filter-branch\b/, reason: "`git filter-branch` is blocked." },
  { pattern: /git\s+reflog\s+expire\b/, reason: "`git reflog expire` is blocked." },
  { pattern: /git\s+update-ref\s+-d\b/, reason: "`git update-ref -d` is blocked." },

  // Destructive filesystem operations against critical locations.
  {
    pattern: /rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(\/|\/Users|\/home|\/etc|\/var|\/usr|\/opt|\/System|\/Library|\$HOME|~\/)/,
    reason: "Recursive forced deletion of system/home paths is blocked.",
  },
  {
    pattern: /rm\s+-[a-z]*f[a-z]*r[a-z]*\s+(\/|\/Users|\/home|\/etc|\/var|\/usr|\/opt|\/System|\/Library|\$HOME|~\/)/,
    reason: "Recursive forced deletion of system/home paths is blocked.",
  },
  { pattern: /sudo\s+rm\b/, reason: "`sudo rm` is blocked." },

  // Disk / system destruction.
  { pattern: /mkfs\b/, reason: "`mkfs` is blocked." },
  { pattern: /dd\s+[^;]*of=\/dev\//, reason: "`dd` to a block device is blocked." },
  { pattern: /\b(shutdown|reboot|halt|poweroff)\b/, reason: "System power commands are blocked." },

  // Fork bomb.
  { pattern: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, reason: "Fork bomb is blocked." },
];

/**
 * Paths that must never be written or edited. Matches anywhere in the path so
 * nested sensitive files are protected too.
 */
export const DENIED_PATHS: Rule[] = [
  // Real .env files (but not the safe .env.example template).
  { pattern: /(^|\/)\.env(?!\.example$)(?:\.|$)/, reason: "Editing .env files is blocked." },
  { pattern: /\/\.ssh\//, reason: "Editing SSH keys is blocked." },
  { pattern: /\/\.aws\//, reason: "Editing AWS credentials is blocked." },
  { pattern: /\/\.gnupg\//, reason: "Editing GPG data is blocked." },
  { pattern: /\/\.config\/gh\//, reason: "Editing GitHub CLI config is blocked." },
  { pattern: /(^|\/)\.netrc$/, reason: "Editing .netrc is blocked." },
  { pattern: /id_rsa/, reason: "Editing private SSH keys is blocked." },
  { pattern: /id_ed25519/, reason: "Editing private SSH keys is blocked." },
  { pattern: /\.pem$/, reason: "Editing PEM key files is blocked." },
  { pattern: /\.key$/, reason: "Editing key files is blocked." },
];

/** Decide whether a bash command should be blocked. */
export function decideBash(command: string): Decision | undefined {
  for (const rule of DENIED_BASH) {
    if (rule.pattern.test(command)) return { block: true, reason: rule.reason };
  }
  return undefined;
}

/** Decide whether a write/edit path should be blocked. */
export function decidePath(path: string): Decision | undefined {
  for (const rule of DENIED_PATHS) {
    if (rule.pattern.test(path)) return { block: true, reason: rule.reason };
  }
  return undefined;
}

/**
 * Pure decision entry point used by tests. Mirrors what the tool_call handler
 * does, minus the pi-specific event plumbing.
 */
export function decide(
  toolName: string,
  input: { command?: string; path?: string },
): Decision | undefined {
  if (toolName === "bash") return decideBash(input.command ?? "");
  if (toolName === "write" || toolName === "edit") return decidePath(input.path ?? "");
  return undefined;
}

// ---------------------------------------------------------------------------
// pi extension wiring
// ---------------------------------------------------------------------------

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, _ctx) => {
    const input = event.input as { command?: string; path?: string };
    return decide(event.toolName, input);
  });
}
