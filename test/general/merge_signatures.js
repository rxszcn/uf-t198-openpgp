import { expect } from 'chai';
import sinon from 'sinon';
import openpgp from '../initOpenpgp.js';

const toHex = bytes => Array.from(bytes, v => v.toString(16).padStart(2, '0')).join('');

const equalBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

/**
 * Clones a signature packet through its serialized form, so that the clone shares no state with the
 * original.
 */
function cloneSignature(signature) {
  const clone = new openpgp.SignaturePacket();
  clone.read(signature.write());
  return clone;
}

/**
 * Returns a signature packet identical to the input except for an extra unknown unhashed subpacket,
 * identified by `marker`. Unhashed subpackets are not covered by the signature, so the resulting
 * packet is still valid, while its serialized form (and hence its identity) differs.
 * The signature material (`writeParams()`) is left untouched.
 */
function withUnhashedMarker(signature, marker) {
  const clone = cloneSignature(signature);
  clone.unhashedSubpackets.push({
    type: 100,
    critical: false,
    body: new Uint8Array([(marker >> 8) & 0xff, marker & 0xff])
  });
  return clone;
}

function makeExpired(signature) {
  const clone = cloneSignature(signature);
  clone.signatureNeverExpires = false;
  clone.signatureExpirationTime = 1;
  return clone;
}

/**
 * Returns a signature packet with a distinct signature material and a distinct unhashed subpacket,
 * so that no two variants are considered duplicates, and no duplicate is found early.
 */
function withDistinctMaterial(signature, marker) {
  const clone = withUnhashedMarker(signature, marker);
  const s = new Uint8Array(clone.params.s);
  s[s.length - 1] ^= marker & 0xff;
  s[s.length - 2] ^= (marker >> 8) & 0xff;
  // MPIs cannot encode zero
  if (s.every(byte => byte === 0)) {
    s[s.length - 1] = 1;
  }
  clone.params = { ...clone.params, s };
  return clone;
}

/**
 * Runs an update merging `n` destination direct-key signatures with `n` source ones, and returns the
 * number of signature material serializations (`writeParams()`) performed.
 */
async function countWriteParams(privateKey, n) {
  const base = privateKey.directSignatures[0];
  const dest = privateKey.clone();
  const source = privateKey.clone();
  dest.directSignatures = Array.from({ length: n }, (_, i) => withDistinctMaterial(base, i));
  source.directSignatures = Array.from({ length: n }, (_, i) => withDistinctMaterial(base, n + i));
  const spy = sinon.spy(openpgp.SignaturePacket.prototype, 'writeParams');
  try {
    const updated = await dest.update(source);
    expect(updated.directSignatures).to.have.length(2 * n);
    return spy.callCount;
  } finally {
    spy.restore();
  }
}

export default () => describe('Signature merging', function() {
  const date = new Date('2020-01-01T00:00:00Z');
  let privateKey;

  const signDirectKey = async () => {
    const signature = new openpgp.SignaturePacket();
    Object.assign(signature, {
      signatureType: openpgp.enums.signature.key,
      hashAlgorithm: openpgp.enums.hash.sha256,
      publicKeyAlgorithm: privateKey.keyPacket.algorithm
    });
    await signature.sign(privateKey.keyPacket, { key: privateKey.keyPacket }, date, false, openpgp.config);
    return signature;
  };

  before(async function() {
    const { privateKey: key } = await openpgp.generateKey({
      userIDs: { name: 'merge signatures' },
      curve: 'ed25519Legacy',
      subkeys: [],
      date,
      format: 'object'
    });
    privateKey = key;
    // the base signature is merged through `Key.update`'s direct-signature path, and keeps being
    // classified as a direct signature when the key is cloned
    privateKey.directSignatures = [await signDirectKey()];
  });

  describe('identity semantics', function() {
    it('keeps valid signatures from the same signer, time and type when their bytes differ', async function() {
      // With `config.nonDeterministicSignaturesViaNotation`, re-signing the same data at the same
      // date yields a different (salt-randomized) packet with the same signer, creation time and
      // signature type.
      const signatureA = await signDirectKey();
      const signatureB = await signDirectKey();
      expect(signatureA.issuerKeyID.toHex()).to.equal(signatureB.issuerKeyID.toHex());
      expect(signatureA.created.getTime()).to.equal(signatureB.created.getTime());
      expect(signatureA.signatureType).to.equal(signatureB.signatureType);
      // the signed area differs (the salt notation), so the packets, and the signatures over them, differ
      expect(equalBytes(signatureA.write(), signatureB.write())).to.be.false;
      // both are valid direct-key signatures, so both must be kept
      const dataToVerify = { key: privateKey.keyPacket };
      await signatureA.verify(privateKey.keyPacket, openpgp.enums.signature.key, dataToVerify, date);
      await signatureB.verify(privateKey.keyPacket, openpgp.enums.signature.key, dataToVerify, date);

      const dest = privateKey.clone();
      const source = privateKey.clone();
      dest.directSignatures = [signatureA];
      source.directSignatures = [signatureB];
      const updated = await dest.update(source, date);
      expect(updated.directSignatures).to.have.length(2);
      expect(updated.directSignatures.map(sig => toHex(sig.write())))
        .to.deep.equal([signatureA, signatureB].map(sig => toHex(sig.write())));
    });

    it('collapses byte-identical duplicates and is idempotent', async function() {
      const base = privateKey.directSignatures[0];
      const dest = privateKey.clone();
      const source = privateKey.clone();
      dest.directSignatures = [withUnhashedMarker(base, 1), withUnhashedMarker(base, 2)];
      source.directSignatures = [withUnhashedMarker(base, 1), withUnhashedMarker(base, 2)];
      const updated = await dest.update(source, date);
      expect(updated.directSignatures).to.have.length(2);
      const updatedAgain = await updated.update(source, date);
      expect(updatedAgain.directSignatures).to.have.length(2);
    });

    it('does not conflate signatures that only differ in the unhashed area', async function() {
      const base = privateKey.directSignatures[0];
      const signatureA = withUnhashedMarker(base, 7);
      const signatureB = withUnhashedMarker(base, 8);
      // same signer, same creation time, same type and same signature material: only the bytes differ
      expect(equalBytes(signatureA.writeParams(), signatureB.writeParams())).to.be.true;
      expect(equalBytes(signatureA.write(), signatureB.write())).to.be.false;
      const dest = privateKey.clone();
      const source = privateKey.clone();
      dest.directSignatures = [signatureA];
      source.directSignatures = [signatureB];
      const updated = await dest.update(source, date);
      expect(updated.directSignatures).to.have.length(2);
    });

    it('filters expired source signatures but does not purge expired destination signatures', async function() {
      const mergeDate = new Date(date.getTime() + 60 * 1000);
      const base = privateKey.directSignatures[0];
      const expired = makeExpired(base);
      const fresh = withUnhashedMarker(base, 3);
      const existing = withUnhashedMarker(base, 4);
      expect(expired.isExpired(mergeDate)).to.be.true;
      expect(fresh.isExpired(mergeDate)).to.be.false;

      const dest = privateKey.clone();
      const source = privateKey.clone();
      dest.directSignatures = [existing];
      source.directSignatures = [expired, fresh];
      const updated = await dest.update(source, mergeDate);
      expect(updated.directSignatures).to.have.length(2);
      expect(updated.directSignatures.map(sig => toHex(sig.write())))
        .to.deep.equal([existing, fresh].map(sig => toHex(sig.write())));

      // signatures that are expired at merge time but already present in the destination are kept
      const destWithExpired = privateKey.clone();
      const sourceWithout = privateKey.clone();
      destWithExpired.directSignatures = [expired];
      sourceWithout.directSignatures = [];
      const unchanged = await destWithExpired.update(sourceWithout, mergeDate);
      expect(unchanged.directSignatures).to.have.length(1);
      expect(equalBytes(unchanged.directSignatures[0].write(), expired.write())).to.be.true;
    });
  });

  describe('complexity guardrails', function() {
    it('serializes signature material a bounded number of times per signature', async function() {
      const n = 200;
      const calls = await countWriteParams(privateKey, n);
      // A pairwise implementation needs ~n^2 serializations (one per compared pair);
      // the merge must only need a constant number per signature.
      expect(calls).to.be.at.most(3 * n, `${calls} serializations for ${n} signatures`);
    });

    it('scales linearly when the number of signatures grows', async function() {
      this.timeout(120000); // eslint-disable-line no-invalid-this
      const small = 100;
      const large = 400;
      const smallCalls = await countWriteParams(privateKey, small);
      const largeCalls = await countWriteParams(privateKey, large);
      expect(smallCalls).to.be.at.most(3 * small);
      expect(largeCalls).to.be.at.most(3 * large);
      // Linear growth would multiply the count by ~4; quadratic growth by ~16.
      expect(largeCalls / smallCalls).to.be.below(8,
        `${smallCalls} -> ${largeCalls} serializations when multiplying the input size by 4`);
    });
  });
});
