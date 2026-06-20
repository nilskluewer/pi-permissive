/**
 * validate.ts — deterministic self-validation of the permission rules.
 *
 * Every `Rule` in `permissions.ts` carries an `examples` contract:
 *   - match:   strings that MUST make the rule fire
 *   - noMatch: strings that MUST NOT make the rule fire
 *
 * This module checks those contracts against the actual regexes, plus two
 * structural invariants that keep the rule list correct as it evolves:
 *
 *   1. ORDERING — if an ASK rule's match-examples also match an earlier DENY
 *      rule, the deny wins (first match wins). We catch the inverse mistake:
 *      a DENY rule whose match-examples are shadowed by an earlier ASK rule
 *      (which would silently turn a deny into an ask).
 *
 *   2. COMPLETENESS — no example string may appear in BOTH a rule's `match`
 *      and another rule's `noMatch` with the same action intent; i.e. we flag
 *      contradictions where the test corpus disagrees about an input.
 *
 * Run it directly:
 *   node --test --experimental-strip-types validate.test.ts
 * or programmatically via `validateRules()` (used by the test suite).
 *
 * This is the contract: you cannot add or change a pattern without proving,
 * deterministically, what it matches and what it rejects.
 */
import {
  BASH_RULES,
  WRITE_RULES,
  READ_RULES,
  type Rule,
} from "./permissions.ts";

export interface RuleValidationFailure {
  ruleIndex: number;
  reason: string;
  kind: "match-failed" | "false-positive" | "shadowed-deny" | "contradiction";
  example?: string;
  detail?: string;
}

export interface ValidationReport {
  ok: boolean;
  rulesChecked: number;
  failures: RuleValidationFailure[];
}

/** Does a single rule fire on `value`? (all patterns AND-ed) */
function ruleFires(rule: Rule, value: string): boolean {
  return rule.patterns.every((p) => p.test(value));
}

/**
 * Validate one rule list. Returns failures (empty = ok).
 *
 * Checks per rule:
 *   - every `examples.match` string makes THIS rule fire (its patterns match)
 *   - no `examples.noMatch` string makes THIS rule fire (no false positives)
 *   - shadowing: for a DENY rule, none of its `match` strings may already be
 *     claimed by an earlier ASK rule (first-match-wins would let ASK win and
 *     the deny would never trigger — a silent downgrade)
 */
function validateRuleList(
  listName: string,
  rules: Rule[],
): RuleValidationFailure[] {
  const failures: RuleValidationFailure[] = [];
  const prefix = (i: number) => `${listName}[${i}]`;

  rules.forEach((rule, i) => {
    // match examples must fire on this rule's patterns
    for (const ex of rule.examples.match) {
      if (!rule.patterns.every((p) => p.test(ex))) {
        failures.push({
          ruleIndex: i,
          kind: "match-failed",
          reason: `${prefix(i)} (${rule.reason}) did not match its own "match" example`,
          example: ex,
        });
      }
    }
    // noMatch examples must NOT fire on this rule's patterns
    for (const ex of rule.examples.noMatch) {
      if (rule.patterns.every((p) => p.test(ex))) {
        failures.push({
          ruleIndex: i,
          kind: "false-positive",
          reason: `${prefix(i)} (${rule.reason}) matched its own "noMatch" example`,
          example: ex,
        });
      }
    }
    // shadowing: an earlier rule that fires on this rule's match examples
    // must NOT be a lower tier (ASK) when this rule is DENY — that would
    // downgrade the deny to an ask silently.
    if (rule.action === "deny") {
      for (const ex of rule.examples.match) {
        for (let j = 0; j < i; j++) {
          const earlier = rules[j];
          if (earlier.action === "ask" && ruleFires(earlier, ex)) {
            failures.push({
              ruleIndex: i,
              kind: "shadowed-deny",
              reason: `${prefix(i)} DENY (${rule.reason}) is shadowed by earlier ASK ${prefix(j)} (${earlier.reason}) on a match example`,
              example: ex,
              detail: `Earlier ASK rule fires first; deny never triggers for this input.`,
            });
          }
        }
      }
    }
    // shadowing the other way: an ASK rule whose match examples already match
    // an earlier DENY is fine (deny wins, which is stricter) — but it usually
    // means the ASK examples are wrong, so warn as a contradiction.
    if (rule.action === "ask") {
      for (const ex of rule.examples.match) {
        for (let j = 0; j < i; j++) {
          const earlier = rules[j];
          if (earlier.action === "deny" && ruleFires(earlier, ex)) {
            failures.push({
              ruleIndex: i,
              kind: "contradiction",
              reason: `${prefix(i)} ASK (${rule.reason}) lists a match example that an earlier DENY ${prefix(j)} (${earlier.reason}) already claims`,
              example: ex,
              detail: `This input will be DENIED, not asked. Fix the example or the rule.`,
            });
          }
        }
      }
    }
  });

  return failures;
}

/**
 * Validate all rule lists. Throws on failure when `throwOnFailure` is true
 * (default), so it can be used as a hard gate in CI / test runs.
 */
export function validateRules(throwOnFailure = true): ValidationReport {
  const all: RuleValidationFailure[] = [
    ...validateRuleList("BASH_RULES", BASH_RULES),
    ...validateRuleList("WRITE_RULES", WRITE_RULES),
    ...validateRuleList("READ_RULES", READ_RULES),
  ];
  const report: ValidationReport = {
    ok: all.length === 0,
    rulesChecked: BASH_RULES.length + WRITE_RULES.length + READ_RULES.length,
    failures: all,
  };
  if (throwOnFailure && !report.ok) {
    const lines = all.map(
      (f) => `  • [${f.kind}] ${f.reason}${f.example ? ` (example: ${JSON.stringify(f.example)})` : ""}`,
    );
    throw new Error(
      `Permission rule validation failed (${all.length} failure(s) across ${report.rulesChecked} rules):\n${lines.join("\n")}`,
    );
  }
  return report;
}

// When run directly (`node --experimental-strip-types validate.ts`), execute
// validation and exit non-zero on failure so it works as a CI step.
if (import.meta.url === `file://${process.argv[1]}`) {
  const report = validateRules(false);
  if (report.ok) {
    console.log(`✓ All ${report.rulesChecked} permission rules validated.`);
    process.exit(0);
  } else {
    console.error(`✗ ${report.failures.length} validation failure(s):`);
    for (const f of report.failures) {
      console.error(`  • [${f.kind}] ${f.reason}`);
      if (f.example) console.error(`      example: ${JSON.stringify(f.example)}`);
      if (f.detail) console.error(`      ${f.detail}`);
    }
    process.exit(1);
  }
}
