import { expect, test as base, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate: every load-bearing claim this page makes, asserted against
 * what the browser actually renders.
 *
 * The rule throughout is that a claim is checked against a value the page
 * COMPUTED, not against a string this file hardcodes. Where the page prints the
 * same fact twice — the pattern's message list and the walkthrough step counter,
 * the Split log's derived keys and the transport panel's key readout, the
 * per-segment byte counts and the "N bytes total" line — the two surfaces are
 * compared to each other. A test that only re-states a literal would survive
 * the page computing nonsense.
 */

const test = base.extend<{ page: Page }>({
  // Any uncaught exception fails the test that provoked it. A page that throws
  // mid-render can leave a stale verdict on screen and still look green.
  page: async ({ page }, use) => {
    const crashes: string[] = [];
    page.on('pageerror', (err) => crashes.push(String(err)));
    await use(page);
    expect(crashes, 'uncaught page exceptions').toEqual([]);
  },
});

const PROTOCOL = (name: string) => `Noise_${name}_25519_AESGCM_SHA256`;

async function load(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#handshake-status')).toHaveText('Handshake complete');
}

/** Select a pattern by name and wait for its handshake to finish. */
async function selectPattern(page: Page, name: string): Promise<void> {
  // The chips live in the Pattern panel; every other panel hides them.
  await page.locator('#tab-pattern').click();
  await page.locator('#all-patterns-disclosure').evaluate((el) => {
    (el as HTMLDetailsElement).open = true;
  });
  await page.locator('.pattern-chip', { hasText: new RegExp(`^${name}$`) }).click();
  await expect(page.locator('#pattern-name')).toHaveText(PROTOCOL(name));
  await expect(page.locator('#handshake-status')).toHaveText('Handshake complete');
}

/** How many handshake messages the PATTERN PANEL says this pattern has. */
async function messageCountFromPatternPanel(page: Page): Promise<number> {
  const listing = (await page.locator('#pattern-messages').innerText()).split('\n');
  return listing.filter(
    (line) => /(->|<-)/.test(line) && !line.includes('(pre-message)')
  ).length;
}

/** Read one `key: value` detail row out of a rendered log entry or attack result. */
async function detail(scope: Locator, key: string): Promise<string | null> {
  return scope.evaluate((root, wanted) => {
    for (const row of Array.from(root.querySelectorAll('.detail-row'))) {
      const k = row.querySelector('.detail-key')?.textContent?.trim().replace(/:$/, '');
      if (k === wanted) return row.querySelector('.detail-value')?.textContent?.trim() ?? null;
    }
    return null;
  }, key);
}

async function stepToLastMessage(page: Page): Promise<number> {
  const next = page.locator('#step-next');
  let guard = 0;
  while (await next.isEnabled()) {
    await next.click();
    if (++guard > 12) throw new Error('step-next never became disabled');
  }
  const counter = await page.locator('#step-counter').textContent();
  return Number(/of (\d+)/.exec(counter ?? '')?.[1]);
}

async function runAttack(page: Page, attack: string): Promise<string> {
  await page.locator(`[data-attack="${attack}"]`).click();
  const result = page.locator(`[data-result="${attack}"]`);
  await expect(result.locator('.badge')).toBeVisible();
  return (await result.innerText()).replace(/\s+/g, ' ');
}

// ---------------------------------------------------------------------------
// The headline verdict, cross-checked against the page's own pattern listing
// ---------------------------------------------------------------------------

test('the handshake completes and the walkthrough agrees with the pattern listing', async ({ page }) => {
  await load(page);

  for (const name of ['NN', 'NK', 'XX', 'IK', 'IKpsk2']) {
    await selectPattern(page, name);

    // The pattern panel and the walkthrough are rendered from the same pattern
    // definition by two different code paths. If they disagree, one of them is
    // describing a handshake that did not happen.
    const expected = await messageCountFromPatternPanel(page);
    expect(expected, `${name} should list at least one handshake message`).toBeGreaterThan(0);

    await page.locator('#tab-walkthrough').click();
    await expect(page.locator('#step-counter')).toHaveText(`Message 1 of ${expected}`);

    const total = await stepToLastMessage(page);
    expect(total, `${name} step counter total`).toBe(expected);
    await expect(page.locator('#step-counter')).toHaveText(`Message ${expected} of ${expected}`);

    await page.locator('#tab-pattern').click();
  }
});

test('the step controls stay alive in both directions', async ({ page }) => {
  await load(page);
  await selectPattern(page, 'XX');
  await page.locator('#tab-walkthrough').click();

  const prev = page.locator('#step-prev');
  const next = page.locator('#step-next');

  await expect(prev).toBeDisabled();
  await expect(next).toBeEnabled();

  const total = await stepToLastMessage(page);
  expect(total).toBeGreaterThan(1);
  await expect(next).toBeDisabled();
  await expect(prev).toBeEnabled();

  // Walking back must re-arm the forward control — a run that has been played
  // to the end is not a run that is over.
  for (let i = 1; i < total; i++) await prev.click();
  await expect(page.locator('#step-counter')).toHaveText(`Message 1 of ${total}`);
  await expect(prev).toBeDisabled();
  await expect(next).toBeEnabled();
});

// ---------------------------------------------------------------------------
// Split(): the derived transport keys reach the transport panel
// ---------------------------------------------------------------------------

test('the transport panel shows the keys the walkthrough says Split derived', async ({ page }) => {
  // Regression: writeMessage/readMessage used to snapshot their step logs BEFORE
  // calling split(), so the Split entry — the one carrying the two derived
  // transport keys — was dropped from every transcript. The walkthrough never
  // showed a Split step and the transport panel rendered its "(derived)"
  // fallback instead of the keys, for every pattern.
  await load(page);
  await selectPattern(page, 'XX');
  await page.locator('#tab-walkthrough').click();
  await stepToLastMessage(page);

  const splitEntry = page
    .locator('#step-info .log-entry')
    .filter({ has: page.locator('.log-operation', { hasText: /^Split$/ }) })
    .first();
  await expect(splitEntry, 'the final message must log Split()').toBeVisible();

  const loggedSend = await detail(splitEntry, 'sendKey');
  const loggedRecv = await detail(splitEntry, 'recvKey');
  expect(loggedSend).toMatch(/^[0-9a-f]{64}$/);
  expect(loggedRecv).toMatch(/^[0-9a-f]{64}$/);
  expect(loggedSend).not.toBe(loggedRecv);

  await page.locator('#tab-transport').click();
  await expect(page.locator('#transport-send-key')).toHaveText(loggedSend!);
  await expect(page.locator('#transport-recv-key')).toHaveText(loggedRecv!);
});

// ---------------------------------------------------------------------------
// Transport: the round trip, and its counters
// ---------------------------------------------------------------------------

test('transport encrypt/decrypt round-trips and the nonce counts the sends', async ({ page }) => {
  await load(page);
  await selectPattern(page, 'IK');
  await page.locator('#tab-transport').click();

  const plaintext = 'attack at dawn';
  await page.locator('#msg-i-to-r').fill(plaintext);
  await page.locator('#send-i-to-r').click();

  // "Decrypted by 🅱" is the receiving CipherState's output, not an echo of the
  // input box: it only reads back if the AEAD actually verified.
  await expect(page.locator('#pt-i-to-r')).toHaveText(plaintext);

  // AES-GCM ciphertext = plaintext bytes + a 16-byte tag, in hex.
  const ct1 = await page.locator('#ct-i-to-r').textContent();
  expect(ct1).toMatch(/^[0-9a-f]+$/);
  expect(ct1!.length / 2).toBe(plaintext.length + 16);
  await expect(page.locator('#i-to-r-nonce')).toHaveText('1');

  // A second send at the next nonce must produce different bytes for identical
  // plaintext — that is the whole reason the counter exists.
  await page.locator('#send-i-to-r').click();
  await expect(page.locator('#i-to-r-nonce')).toHaveText('2');
  const ct2 = await page.locator('#ct-i-to-r').textContent();
  expect(ct2).not.toBe(ct1);
  await expect(page.locator('#pt-i-to-r')).toHaveText(plaintext);

  // The other lane has its own key and its own counter; it must not have moved.
  await expect(page.locator('#r-to-i-nonce')).toHaveText('0');
  await page.locator('#msg-r-to-i').fill('roger');
  await page.locator('#send-r-to-i').click();
  await expect(page.locator('#pt-r-to-i')).toHaveText('roger');
  await expect(page.locator('#r-to-i-nonce')).toHaveText('1');
  await expect(page.locator('#i-to-r-nonce')).toHaveText('2');

  // "New session" must return the counters to zero AND leave the controls
  // usable — but it may only do so by changing the KEYS. The dedicated test
  // below is what makes zeroing here legitimate rather than fatal.
  const keyBeforeReset = await page.locator('#transport-send-key').textContent();
  await page.locator('#reset-transport-btn').click();
  await expect(page.locator('#i-to-r-nonce')).toHaveText('0');
  await expect(page.locator('#r-to-i-nonce')).toHaveText('0');
  await expect(page.locator('#ct-i-to-r')).toHaveText('');
  await expect(page.locator('#transport-send-key')).not.toHaveText(keyBeforeReset ?? '');
  await page.locator('#send-i-to-r').click();
  await expect(page.locator('#pt-i-to-r')).toHaveText(plaintext);
  await expect(page.locator('#i-to-r-nonce')).toHaveText('1');
});

test('a new session never replays a (key, nonce) pair', async ({ page }) => {
  // The catastrophe this lab exists to teach, guarded in the lab itself.
  //
  // "Reset" used to call setNonce(0) on the SAME CipherState objects, so
  // send -> Reset -> send encrypted under an identical (key, nonce) pair. It was
  // demonstrable in one click: identical plaintext produced BYTE-IDENTICAL
  // ciphertext across the reset. With AES-GCM that hands an observer the XOR of
  // the two plaintexts and forfeits the authenticator.
  //
  // The old version of the test above asserted the counters returned to zero and
  // stopped there, so it did not merely miss the bug — it REQUIRED it.
  await load(page);
  await selectPattern(page, 'IK');
  await page.locator('#tab-transport').click();

  const plaintext = 'IDENTICAL PLAINTEXT';
  await page.locator('#msg-i-to-r').fill(plaintext);
  await page.locator('#send-i-to-r').click();
  await expect(page.locator('#i-to-r-nonce')).toHaveText('1');
  const ctBefore = await page.locator('#ct-i-to-r').textContent();
  const sendKeyBefore = await page.locator('#transport-send-key').textContent();
  const recvKeyBefore = await page.locator('#transport-recv-key').textContent();
  expect(ctBefore).toMatch(/^[0-9a-f]+$/);

  await page.locator('#reset-transport-btn').click();
  await expect(page.locator('#i-to-r-nonce')).toHaveText('0');

  // Zeroing the counter is only safe because BOTH directions are keyed anew.
  const sendKeyAfter = await page.locator('#transport-send-key').textContent();
  const recvKeyAfter = await page.locator('#transport-recv-key').textContent();
  expect(sendKeyAfter, 'send key must change when the counter rewinds').not.toBe(sendKeyBefore);
  expect(recvKeyAfter, 'recv key must change when the counter rewinds').not.toBe(recvKeyBefore);

  // The observable consequence: identical plaintext at the identical counter
  // must NOT reproduce the identical ciphertext.
  await page.locator('#msg-i-to-r').fill(plaintext);
  await page.locator('#send-i-to-r').click();
  await expect(page.locator('#i-to-r-nonce')).toHaveText('1');
  const ctAfter = await page.locator('#ct-i-to-r').textContent();
  expect(
    ctAfter,
    'same plaintext at the same nonce produced the same bytes — the key was reused',
  ).not.toBe(ctBefore);

  // And the session still works: the receiver really decrypts it.
  await expect(page.locator('#pt-i-to-r')).toHaveText(plaintext);
});

test('the displayed nonce counts records, and identical plaintext never repeats bytes', async ({
  page,
}) => {
  // Regression: encryptWithAd read `this.n`, awaited WebCrypto, and only then
  // incremented, so two overlapping sends sealed two plaintexts under one
  // (key, nonce) pair — 200 of 200 concurrent pairs, with a byte-identical
  // keystream prefix. The counter meanwhile showed 2, describing a state the
  // records were not in.
  //
  // The invariant between two rendered things: the number shown in
  // #i-to-r-nonce must equal the number of records this lane has sealed, and no
  // two records may ever be byte-identical.
  await load(page);
  await selectPattern(page, 'IK');
  await page.locator('#tab-transport').click();

  const seen: string[] = [];
  const plaintext = 'IDENTICAL PLAINTEXT';
  for (let i = 1; i <= 4; i++) {
    await page.locator('#msg-i-to-r').fill(plaintext);
    await page.locator('#send-i-to-r').click();
    await expect(page.locator('#pt-i-to-r')).toHaveText(plaintext);
    await expect(
      page.locator('#i-to-r-nonce'),
      'the counter must equal the number of records sealed',
    ).toHaveText(String(i));
    const ct = await page.locator('#ct-i-to-r').textContent();
    expect(ct).toMatch(/^[0-9a-f]+$/);
    seen.push(ct!);
  }
  expect(seen, 'four sends must have been recorded').toHaveLength(4);
  expect(
    new Set(seen).size,
    'identical plaintext produced identical ciphertext — the nonce repeated',
  ).toBe(seen.length);
});

test('two sends fired in one tick cannot share a nonce', async ({ page }) => {
  // The reachable route to the bug above: a double-clicked send button. Both
  // handlers ran to their first await before either incremented, so both sealed
  // under nonce 0. The panel overwrites #ct-i-to-r on each send, so the
  // collision leaves no trace in the DOM — the only unfoolable witness is the
  // IV handed to AES-GCM. Record every one and require them to be distinct.
  await page.addInitScript(() => {
    const ivs: string[] = [];
    (window as unknown as { __ivs: string[] }).__ivs = ivs;
    const subtle = crypto.subtle;
    const original = subtle.encrypt.bind(subtle);
    subtle.encrypt = ((alg: AesGcmParams, key: CryptoKey, data: BufferSource) => {
      if (alg && alg.name === 'AES-GCM' && alg.iv) {
        ivs.push(Array.from(new Uint8Array(alg.iv as ArrayBuffer)).join(','));
      }
      return original(alg, key, data);
    }) as typeof subtle.encrypt;
  });

  await load(page);
  await selectPattern(page, 'IK');
  await page.locator('#tab-transport').click();

  // Everything before this point (the handshakes) is not under test.
  const before = await page.evaluate(
    () => (window as unknown as { __ivs: string[] }).__ivs.length,
  );

  await page.locator('#msg-i-to-r').fill('IDENTICAL PLAINTEXT');
  await page.evaluate(() => {
    const btn = document.getElementById('send-i-to-r') as HTMLButtonElement;
    btn.click();
    btn.click();
  });
  await expect(page.locator('#pt-i-to-r')).toHaveText('IDENTICAL PLAINTEXT');
  await page.waitForTimeout(400);

  const sealed = await page.evaluate(
    (n) => (window as unknown as { __ivs: string[] }).__ivs.slice(n),
    before,
  );
  expect(sealed.length, 'at least one record must have been sealed').toBeGreaterThan(0);
  expect(
    new Set(sealed).size,
    `${sealed.length} records went out under ${new Set(sealed).size} distinct nonces — a repeat is (key, nonce) reuse`,
  ).toBe(sealed.length);

  // And the counter must account for exactly the records that went out.
  await expect(
    page.locator('#i-to-r-nonce'),
    'the counter must equal the number of records sealed',
  ).toHaveText(String(sealed.length));
});

test('the transport readout retires when the input it described changes', async ({ page }) => {
  // Regression: "Decrypted by 🅱" is a claim about one ciphertext under one key.
  // It used to stay on screen after the learner edited the plaintext, and after
  // a rekey replaced the key it was produced under.
  await load(page);
  await selectPattern(page, 'NN');
  await page.locator('#tab-transport').click();

  await page.locator('#msg-i-to-r').fill('first');
  await page.locator('#send-i-to-r').click();
  await expect(page.locator('#pt-i-to-r')).toHaveText('first');

  await page.locator('#msg-i-to-r').fill('second');
  await expect(page.locator('#pt-i-to-r')).toHaveText('');
  await expect(page.locator('#ct-i-to-r')).toHaveText('');

  // Rekey: the displayed key changes, so anything computed under the old one
  // must go with it, and the status line must say why.
  await page.locator('#send-i-to-r').click();
  await expect(page.locator('#pt-i-to-r')).toHaveText('second');
  const keyBefore = await page.locator('#transport-send-key').textContent();
  await page.locator('#rekey-i-btn').click();
  await expect(page.locator('#transport-send-key')).not.toHaveText(keyBefore!);
  await expect(page.locator('#pt-i-to-r')).toHaveText('');
  await expect(page.locator('#transport-error')).toContainText('rekeyed');
  await expect(page.locator('#transport-error')).toContainText('old k');

  // Rekeying one direction must not disturb the other, or kill the controls.
  await page.locator('#msg-i-to-r').fill('after rekey');
  await page.locator('#send-i-to-r').click();
  await expect(page.locator('#pt-i-to-r')).toHaveText('after rekey');
});

// ---------------------------------------------------------------------------
// Break it: every failure path reaches a verdict AND names the cause
// ---------------------------------------------------------------------------

const HELD = 'Attack failed — defense held';
const SUCCEEDED = 'Attack succeeded';
const NA = 'Not applicable to this pattern';
const NO_VERDICT = 'Could not run — no verdict';
const BADGES = [HELD, SUCCEEDED, NA, NO_VERDICT];

/**
 * pattern → attack → { badge, cause }. Every cell is a state the panel can
 * reach; each one must land on the right badge and say why in words a learner
 * can act on.
 */
const ATTACK_MATRIX: Array<{ pattern: string; attack: string; badge: string; cause: RegExp }> = [
  { pattern: 'NN', attack: 'bitflip', badge: HELD, cause: /authentication tag detected the tamper/i },
  { pattern: 'NN', attack: 'noncereuse', badge: SUCCEEDED, cause: /XOR of ciphertexts leaks XOR of plaintexts/i },
  { pattern: 'NN', attack: 'replay', badge: SUCCEEDED, cause: /NN has no built-in replay protection/i },
  // NN owns no static keys, so the "compromise the statics afterwards"
  // experiment has nothing to compromise and runs zero decryptions. It used to
  // badge HELD and print "AEAD rejects the static-only key" anyway — crediting
  // a defense that was never exercised. NN IS forward secret; the summary says
  // so, and says why this panel is not the thing that proves it.
  { pattern: 'NN', attack: 'forwardsecrecy', badge: NA, cause: /Nothing was run/i },
  { pattern: 'XX', attack: 'forwardsecrecy', badge: HELD, cause: /AEAD rejected every one/i },
  { pattern: 'NK', attack: 'forwardsecrecy', badge: HELD, cause: /AEAD rejected every one/i },
  // Nothing was run: these must NOT be dressed up as a security result.
  { pattern: 'NN', attack: 'rsswap', badge: NA, cause: /NN has no pre-known responder static key/i },
  { pattern: 'NN', attack: 'pskmismatch', badge: NA, cause: /NN has no PSK to mismatch/i },
  { pattern: 'XX', attack: 'rsswap', badge: NA, cause: /XX has no pre-known responder static key/i },
  // A pre-known rs is trusted unconditionally — the impersonator gets in.
  { pattern: 'IK', attack: 'rsswap', badge: SUCCEEDED, cause: /IK accepted the forged responder static key/i },
  { pattern: 'NK', attack: 'rsswap', badge: SUCCEEDED, cause: /NK accepted the forged responder static key/i },
  // …unless a PSK the attacker never had is mixed in.
  { pattern: 'IKpsk2', attack: 'rsswap', badge: HELD, cause: /not the pre-shared key/i },
  { pattern: 'IKpsk2', attack: 'pskmismatch', badge: HELD, cause: /PSK mismatch caused the handshake to fail/i },
];

for (const { pattern, attack, badge, cause } of ATTACK_MATRIX) {
  test(`break-it: ${pattern} / ${attack} → ${badge}`, async ({ page }) => {
    await load(page);
    await selectPattern(page, pattern);
    await page.locator('#tab-breakit').click();
    const text = await runAttack(page, attack);
    expect(text, 'badge').toContain(badge);
    expect(text, 'the verdict must name its cause').toMatch(cause);
    // No other badge may appear alongside it.
    for (const other of BADGES.filter((b) => b !== badge)) {
      expect(text, `must not also render "${other}"`).not.toContain(other);
    }
  });
}

test('the responder-static swap is an impersonation, demonstrated in bytes', async ({ page }) => {
  // Regression: this simulation used to hand the initiator a forged rs and then
  // run the handshake against the HONEST responder. That failed for want of a
  // matching key on either side, and the panel reported the failure as "IK
  // rejected the forged responder static key — defense held" — telling the
  // learner that IK detects substituted static keys, which is the opposite of
  // what IK does and the opposite of what its own card says.
  await load(page);
  await selectPattern(page, 'IK');
  await page.locator('#tab-breakit').click();
  await runAttack(page, 'rsswap');

  const scope = page.locator('[data-result="rsswap"]');
  const real = await detail(scope, 'realResponderRS');
  const forged = await detail(scope, 'forgedRS');
  const initiatorKey = await detail(scope, 'initiatorTransportKey');
  const attackerKey = await detail(scope, 'attackerTransportKey');

  expect(real).toMatch(/^[0-9a-f]{64}$/);
  expect(forged).toMatch(/^[0-9a-f]{64}$/);
  expect(forged, 'the substituted key must differ from the real one').not.toBe(real);
  // The impersonation itself: the attacker ends the handshake holding exactly
  // the key the initiator believes it shares with the real responder.
  expect(initiatorKey).toMatch(/^[0-9a-f]{64}$/);
  expect(attackerKey).toBe(initiatorKey);

  // And IKpsk2, run identically, must never reach a shared transport key.
  await selectPattern(page, 'IKpsk2');
  await page.locator('#tab-breakit').click();
  await runAttack(page, 'rsswap');
  expect(await detail(scope, 'attackerTransportKey')).toBeNull();
});

test('the bit-flip result is internally consistent: one byte, one bit', async ({ page }) => {
  await load(page);
  await page.locator('#tab-breakit').click();
  await runAttack(page, 'bitflip');

  const scope = page.locator('[data-result="bitflip"]');
  const clean = await detail(scope, 'ciphertext');
  const tampered = await detail(scope, 'tampered');
  expect(clean).toMatch(/^[0-9a-f]+$/);
  expect(tampered).toHaveLength(clean!.length);

  const a = Buffer.from(clean!, 'hex');
  const b = Buffer.from(tampered!, 'hex');
  const differing = [...a].map((v, i) => v ^ b[i]).map((v, i) => ({ i, v })).filter((d) => d.v !== 0);
  expect(differing, 'exactly one byte should differ').toHaveLength(1);
  expect(differing[0].v, 'and by exactly one bit — 0x80').toBe(0x80);
  expect(differing[0].i, 'the first byte, as the card says').toBe(0);
});

test('nonce reuse is demonstrated, not asserted: the two XORs agree', async ({ page }) => {
  // The page computes the leak twice by independent routes — once from the two
  // ciphertexts an attacker could have recorded, once from the two plaintexts.
  // If they match, keystream reuse really did expose the plaintext relationship.
  await load(page);
  await page.locator('#tab-breakit').click();
  await runAttack(page, 'noncereuse');

  const scope = page.locator('[data-result="noncereuse"]');
  const ct1 = await detail(scope, 'ciphertext1');
  const ct2 = await detail(scope, 'ciphertext2');
  const ctXor = await detail(scope, 'ciphertextXOR');
  const ptXor = await detail(scope, 'recoveredXOR');

  expect(ct1).toMatch(/^[0-9a-f]+$/);
  expect(ct2).not.toBe(ct1);
  expect(ctXor, 'attacker-side XOR must equal plaintext-side XOR').toBe(ptXor);
  expect(ctXor, 'a zero XOR would prove nothing').not.toMatch(/^0+$/);

  // Recompute it here rather than trusting either of the page's two numbers.
  const a = Buffer.from(ct1!, 'hex');
  const b = Buffer.from(ct2!, 'hex');
  const n = Buffer.from(ctXor!, 'hex').length;
  const recomputed = Buffer.from([...a.subarray(0, n)].map((v, i) => v ^ b[i])).toString('hex');
  expect(recomputed).toBe(ctXor);
});

test('break-it verdicts retire when the pattern they describe changes', async ({ page }) => {
  // Regression: "IK accepted the forged responder static key" stayed on screen
  // after switching to NN, a pattern that attack was never run against.
  await load(page);
  await selectPattern(page, 'IK');
  await page.locator('#tab-breakit').click();
  expect(await runAttack(page, 'rsswap')).toContain(SUCCEEDED);

  await page.locator('#tab-pattern').click();
  await selectPattern(page, 'NN');
  await page.locator('#tab-breakit').click();
  await expect(page.locator('[data-result="rsswap"]')).toHaveText('');
  await expect(page.locator('[data-result="rsswap"] .badge')).toHaveCount(0);
});

test('an attack already in flight cannot repaint the panel after the pattern changes', async ({
  page,
}) => {
  // Regression: clearBreakItResults() wipes the slot on pattern change, but an
  // attack started a moment earlier finished afterwards and wrote its verdict
  // into the cleared slot — "IK accepted the forged responder static key"
  // rendered under the NN heading. Each attack measured 0–8.6 ms, so a human
  // was unlikely to hit it; nothing bounded it either way.
  //
  // Fire the attack and the pattern switch inside one tick, which is the state
  // the guard exists for.
  await load(page);
  await selectPattern(page, 'IK');
  await page.locator('#tab-breakit').click();

  // Both clicks inside ONE evaluate: no round trip between them, so the attack
  // is genuinely still in flight when the pattern changes. Anything less and
  // the attack (7 ms for IK/rsswap) simply finishes first and the test proves
  // nothing.
  await page.evaluate(() => {
    document.querySelector<HTMLElement>('[data-attack="rsswap"]')!.click();
    (document.getElementById('all-patterns-disclosure') as HTMLDetailsElement).open = true;
    Array.from(document.querySelectorAll<HTMLElement>('.pattern-chip'))
      .find((c) => c.textContent?.trim() === 'NN')!
      .click();
  });
  await expect(page.locator('#pattern-name')).toHaveText(PROTOCOL('NN'));
  await expect(page.locator('#handshake-status')).toHaveText('Handshake complete');

  await page.locator('#tab-breakit').click();
  // Give any stranded continuation ample time to land if it is going to.
  await page.waitForTimeout(500);
  const stranded = await page.locator('[data-result="rsswap"]').innerText();
  expect(
    stranded,
    'a verdict computed against IK must never be painted under NN',
  ).not.toContain('IK');
  expect(stranded.trim(), 'the slot must stay empty, not hold a foreign verdict').toBe('');
});

test('a pattern switched mid-handshake never leaves the previous handshake on screen', async ({
  page,
}) => {
  // Regression: selectPattern() set currentPattern synchronously and then
  // awaited runFullHandshake(). A SLOWER pattern started FIRST settled LAST and
  // its result overwrote the newer selection's — measured at 300 of 300 for
  // XX-then-NN, XK-then-NN and IKpsk2-then-NN when both were started in the same
  // tick. The page then showed NN's name above XX's handshake, transport keys
  // and walkthrough.
  await load(page);
  await page.locator('#tab-pattern').click();
  await page.locator('#all-patterns-disclosure').evaluate((el) => {
    (el as HTMLDetailsElement).open = true;
  });

  // Click XX (3 messages, the slower handshake) then NN (2 messages) in ONE
  // tick, so both handshakes are in flight together.
  await page.evaluate(() => {
    const chip = (name: string) =>
      Array.from(document.querySelectorAll<HTMLElement>('.pattern-chip')).find(
        (c) => c.textContent?.trim() === name,
      )!;
    chip('XX').click();
    chip('NN').click();
  });
  await expect(page.locator('#pattern-name')).toHaveText(PROTOCOL('NN'));
  await expect(page.locator('#handshake-status')).toHaveText('Handshake complete');
  await page.waitForTimeout(500); // let the losing handshake settle

  // The name says NN. Every rendered value must belong to NN too. NN is two
  // messages; XX is three — so the walkthrough is the tell.
  await expect(page.locator('#pattern-name'), 'the label must still say NN').toHaveText(
    PROTOCOL('NN'),
  );
  const listed = await messageCountFromPatternPanel(page);
  expect(listed, 'NN lists two handshake messages').toBe(2);

  await page.locator('#tab-walkthrough').click();
  const total = await stepToLastMessage(page);
  expect(
    total,
    'the walkthrough must render NN’s handshake, not the one still in flight',
  ).toBe(listed);
});

test('the forward-secrecy verdict reports how many keys it actually tried', async ({ page }) => {
  // Regression: the panel printed "Stealing both static private keys after the
  // fact does NOT decrypt the recorded record — AEAD rejects the static-only
  // key" for all 13 patterns, while 4 of them (NN, NK, KN, IN) attempted no
  // decryption at all and 3 of them (NK, KN, IN) own exactly ONE static key.
  // The only e2e test covering this panel ran NN — the one pattern where the
  // wrong key count was masked by a special case.
  //
  // The invariant: the badge and the attempt count must agree, in both
  // directions, for every pattern the panel can be pointed at.
  await load(page);
  const scope = page.locator('[data-result="forwardsecrecy"]');
  let heldSeen = 0;
  let naSeen = 0;

  for (const name of ['NN', 'NK', 'KN', 'IN', 'XX', 'IK', 'IKpsk2']) {
    await selectPattern(page, name);
    await page.locator('#tab-breakit').click();
    const text = await runAttack(page, 'forwardsecrecy');

    const tried = await detail(scope, 'candidate keys tried');
    expect(tried, `${name} must report how many candidate keys it tried`).not.toBeNull();
    const count = Number(/^(\d+)/.exec(tried!)![1]);

    if (text.includes(HELD)) {
      expect(count, `${name} badges "held", so it must have rejected something`).toBeGreaterThan(0);
      expect(text, `${name}`).toContain('AEAD rejected every one');
      heldSeen++;
    } else {
      expect(text, `${name} tried nothing, so it must badge n/a`).toContain(NA);
      expect(count, `${name} badges n/a, so nothing may have been tried`).toBe(0);
      expect(text, `${name} ran nothing and may not claim a rejection`).not.toContain(
        'AEAD rejected',
      );
      naSeen++;
    }

    // And the compromise it describes must match the keys the pattern owns.
    const holds = await detail(scope, 'attacker holds');
    expect(holds, `${name} must say what the attacker holds`).toBeTruthy();
    if (count === 3) {
      expect(holds, `${name} formed ss+se+es, so it owns two statics`).toContain(
        'both static private keys',
      );
    } else if (count === 1) {
      expect(holds, `${name} owns one static key — "both" would be a lie`).not.toContain(
        'both static private keys',
      );
      expect(holds, `${name}`).toContain('the only static key this pattern has');
    }
    await page.locator('#tab-pattern').click();
  }

  expect(heldSeen, 'most patterns must reach a real "held" verdict').toBeGreaterThan(0);
  expect(naSeen, 'NN has no statics, so it must badge n/a').toBeGreaterThan(0);
});

// ---------------------------------------------------------------------------
// The on-the-wire byte view: parts sum to the whole, identity hiding visible
// ---------------------------------------------------------------------------

test('wire-block segments sum to the message total, on every step', async ({ page }) => {
  await load(page);

  for (const name of ['NN', 'XX', 'IK', 'IKpsk2']) {
    await selectPattern(page, name);
    await page.locator('#tab-walkthrough').click();
    const total = await messageCountFromPatternPanel(page);

    for (let step = 1; step <= total; step++) {
      const { parts, whole } = await page.evaluate(() => {
        const blocks = Array.from(document.querySelectorAll('#wire-blocks .wire-block-bytes'));
        const parts = blocks.map((b) => Number(/(\d+)/.exec(b.textContent ?? '')?.[1] ?? NaN));
        const note = document.querySelector('#wire-blocks .wire-blocks-note')?.textContent ?? '';
        return { parts, whole: Number(/(\d+) bytes total/.exec(note)?.[1] ?? NaN) };
      });
      expect(parts.length, `${name} step ${step} should segment the message`).toBeGreaterThan(0);
      expect(parts.some(Number.isNaN)).toBe(false);
      expect(Number.isNaN(whole)).toBe(false);
      expect(
        parts.reduce((a, b) => a + b, 0),
        `${name} step ${step}: segment bytes must account for the whole message`
      ).toBe(whole);
      if (step < total) await page.locator('#step-next').click();
    }
    await page.locator('#tab-pattern').click();
  }
});

test('the wire view shows a static key in the clear only when no k exists yet', async ({ page }) => {
  await load(page);

  // IX sends `-> e, s` first: no DH has run, so the identity rides in cleartext.
  await selectPattern(page, 'IX');
  await page.locator('#tab-walkthrough').click();
  await expect(page.locator('#wire-blocks')).toContainText('🔓');
  await expect(page.locator('#wire-blocks')).not.toContainText('🔒');
  await expect(page.locator('.wire-blocks-note')).toContainText('in the clear');

  // XX sends its statics only after `ee` has produced a k, so both are encrypted.
  await selectPattern(page, 'XX');
  await page.locator('#tab-walkthrough').click();
  await page.locator('#step-next').click(); // message 2: <- e, ee, s, es
  await expect(page.locator('#wire-blocks')).toContainText('🔒');
  await expect(page.locator('#wire-blocks')).not.toContainText('🔓');
  await expect(page.locator('.wire-blocks-note')).toContainText('encrypted');
});

// ---------------------------------------------------------------------------
// The [hidden] trap, and the banner that used to outlive its pattern
// ---------------------------------------------------------------------------

test('nothing carrying the hidden attribute is still painted', async ({ page }) => {
  // Regression: `.whats-new-banner { display: flex }` outranks the UA sheet's
  // `[hidden] { display: none }`, so `banner.hidden = true` was a silent no-op.
  await load(page);
  await selectPattern(page, 'NX'); // not on the guided path — banner must retire

  const leaks = await page.evaluate(() =>
    Array.from(document.querySelectorAll('[hidden]'))
      .filter((el) => getComputedStyle(el as HTMLElement).display !== 'none')
      .map((el) => ({ id: (el as HTMLElement).id, cls: (el as HTMLElement).className.toString() }))
  );
  expect(leaks, `elements marked hidden that still render: ${JSON.stringify(leaks)}`).toEqual([]);
});

test("the what's-new banner describes the pattern on screen, or nothing", async ({ page }) => {
  await load(page);

  const banner = page.locator('#whats-new-banner');
  const body = page.locator('#whats-new-text');

  // NN opens the guided path.
  await expect(banner).toBeVisible();
  await expect(body).toContainText('Start here');

  await selectPattern(page, 'NK');
  await expect(banner).toBeVisible();
  await expect(body).toContainText('New vs NN');

  await selectPattern(page, 'XX');
  await expect(banner).toBeVisible();
  await expect(body).toContainText('New vs NK');

  // Off the guided path there is nothing to say — and saying the last pattern's
  // line instead would be a claim about a pattern the learner has left.
  await selectPattern(page, 'NX');
  await expect(banner).toBeHidden();

  await selectPattern(page, 'IKpsk2');
  await expect(banner).toBeVisible();
  await expect(body).toContainText('New vs XX');
});

// ---------------------------------------------------------------------------
// Comparison panel: what it prints must match the selected pattern's own panel
// ---------------------------------------------------------------------------

test('the comparison table agrees with each pattern panel about its properties', async ({ page }) => {
  await load(page);

  // Both surfaces encode the property value in a `security-<value>` class, so
  // they can be compared without parsing icons out of the visible text.
  // (`security-value` is the element's own class name, not a value.)
  for (const name of ['NN', 'XX', 'IK', 'IKpsk2']) {
    await selectPattern(page, name);
    const panelValues = await page.locator('#security-properties').evaluate((root) =>
      Array.from(root.querySelectorAll('.security-value')).map(
        (el) =>
          Array.from(el.classList)
            .filter((c) => c.startsWith('security-') && c !== 'security-value')
            .map((c) => c.slice('security-'.length))[0] ?? null
      )
    );
    expect(panelValues, `${name}: pattern panel should print three properties`).toHaveLength(3);
    expect(panelValues.some((v) => v === null)).toBe(false);

    await page.locator('#tab-comparison').click();
    const tableValues = await page.locator('#comparison-table').evaluate(
      (root, pattern) =>
        ['senderAuth', 'forwardSecrecy', 'identityHiding'].map((prop) => {
          const cell = root.querySelector(`.compare-cell[data-pattern="${pattern}"][data-prop="${prop}"]`);
          return cell
            ? Array.from(cell.classList)
                .filter((c) => c.startsWith('security-'))
                .map((c) => c.slice('security-'.length))[0] ?? null
            : null;
        }),
      name
    );

    expect(tableValues, `${name}: comparison table vs pattern panel`).toEqual(panelValues);
    await page.locator('#tab-pattern').click();
  }
});
