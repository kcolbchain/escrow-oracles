(function(){'use strict';

const STATES = { CREATED: 'created', FUNDED: 'funded', DELIVERED: 'delivered', SETTLED: 'settled' };

class EscrowSimulator {
  constructor(opts) {
    this.id = opts.id || 'esc-' + Date.now();
    this.amount = opts.amount || 100;
    this.k = opts.k || 2;
    this.n = opts.n || 3;
    this.attestationWindow = opts.attestationWindow || 300;
    this.state = STATES.CREATED;
    this.attestations = [];
    this.log = [];
  }

  fund() {
    if (this.state !== STATES.CREATED) throw new Error('Must be CREATED to fund');
    this.state = STATES.FUNDED;
    this._log('funded', `Escrow ${this.id} funded with ${this.amount}`);
  }

  deliver() {
    if (this.state !== STATES.FUNDED) throw new Error('Must be FUNDED to deliver');
    this.state = STATES.DELIVERED;
    this._log('delivered', 'Deliverable submitted');
  }

  attest(oracleId, result) {
    if (this.state !== STATES.DELIVERED) throw new Error('Must be DELIVERED to attest');
    this.attestations.push({ oracleId, result, ts: Date.now() });
    this._log('attest', `Oracle ${oracleId} attests: ${result}`);
    return this._checkThreshold();
  }

  _checkThreshold() {
    const passed = this.attestations.filter(a => a.result === true).length;
    if (passed >= this.k && this.state === STATES.DELIVERED) {
      this.state = STATES.SETTLED;
      this._log('settled', `Threshold reached (${passed}/${this.k}), escrow settled`);
      return true;
    }
    return false;
  }

  _log(type, msg) {
    this.log.push({ type, msg, ts: Date.now() });
  }

  reset() {
    this.state = STATES.CREATED;
    this.attestations = [];
    this.log = [];
  }
}

// ---- Tuning mode ----
function tuningGame() {
  const results = [];
  for (let k = 1; k <= 5; k++) {
    for (let n = k; n <= 6; n++) {
      const sim = new EscrowSimulator({ id: `tune-${k}-${n}`, k, n });
      try {
        sim.fund(); sim.deliver();
        for (let i = 0; i < n; i++) sim.attest('o' + i, i < k);
        results.push({ k, n, settled: sim.state === STATES.SETTLED, attCount: sim.attestations.length });
      } catch(e) { results.push({ k, n, error: e.message }); }
    }
  }
  return results;
}

// ---- Adversarial mode ----
function adversarialGame() {
  const sim = new EscrowSimulator({ id: 'adversarial', k: 2, n: 4 });
  sim.fund(); sim.deliver();
  const attacks = [];
  // attack 1: false attestations flood
  for (let i = 0; i < 3; i++) sim.attest('evil-' + i, false);
  attacks.push({ type: 'false-flood', settled: sim.state === STATES.SETTLED, count: 3 });
  // attack 2: colluding oracles
  sim.attest('colluding-1', true);
  sim.attest('colluding-2', true);
  attacks.push({ type: 'collusion', settled: sim.state === STATES.SETTLED });
  return attacks;
}

// ---- Compose mode ----
function composeGame() {
  const chain = [];
  const a = new EscrowSimulator({ id: 'alice-bob', amount: 50, k: 1, n: 2 });
  const b = new EscrowSimulator({ id: 'bob-carol', amount: 30, k: 1, n: 2 });
  a.fund(); a.deliver(); a.attest('o1', true);
  chain.push({ step: 1, settled: a.state === STATES.SETTLED });
  if (a.state === STATES.SETTLED) {
    b.fund(); b.deliver(); b.attest('o2', true);
    chain.push({ step: 2, settled: b.state === STATES.SETTLED });
  }
  return chain;
}

window.EscrowSimulator = EscrowSimulator;
window.tuningGame = tuningGame;
window.adversarialGame = adversarialGame;
window.composeGame = composeGame;
window.STATES = STATES;
})();
