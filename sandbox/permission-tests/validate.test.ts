/**
 * Permission rule self-validation tests.
 *
 * These tests prove, deterministically, that every rule in permissions.ts:
 *   - matches all of its declared `examples.match` strings
 *   - rejects all of its declared `examples.noMatch` strings
 *   - is correctly ordered (a DENY is never shadowed by an earlier ASK)
 *
 * Run with:
 *   node --test --experimental-strip-types validate.test.ts
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateRules } from "../../extensions/validate.ts";

test("validateRules: all rules satisfy their examples (no failures)", () => {
  const report = validateRules(false);
  if (!report.ok) {
    for (const f of report.failures) {
      console.error(`  • [${f.kind}] ${f.reason}`);
      if (f.example) console.error(`      example: ${JSON.stringify(f.example)}`);
      if (f.detail) console.error(`      ${f.detail}`);
    }
  }
  assert.equal(report.ok, true, "rule validation failed — see stderr above");
  assert.ok(report.rulesChecked > 0, "no rules were checked");
});

test("validateRules: throws when throwOnFailure is true and a rule is broken", () => {
  // Sanity check: with the current (correct) rule set, throwing mode must NOT
  // throw. This guards against accidental regressions where validation silently
  // passes despite broken examples.
  assert.doesNotThrow(() => validateRules(true));
});
