/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path (`NT_BASELINE_CAPTURE=1`) so the baseline and the check
 * cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  /*
   * The two shared-top-bar controls: fill-less buttons whose 1px color-mix
   * border is their only delineator, at 2.45:1 against the always-dark bar in
   * every state and both viewports (the bar ignores the page theme, so the
   * number does not move). The same bar is baselined fleet-wide — timing-oracle
   * records it at 1.49, mac-race at 1.51; it reads differently here only
   * because this lab's accent mixes brighter — and brightening one lab's
   * border is exactly the per-lab drift the header policy warns against. Fix
   * as a deliberate fleet pass, then delete these two entries.
   */
  'control-boundary|a.cl-btn': { ratio: 2.45, required: 3.0, unverified: false },
};
