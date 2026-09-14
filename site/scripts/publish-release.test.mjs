// jade:ring local
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const inventoryType = 'https://aflock.ai/attestations/file-inventory/v0.1';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const envelope = (statement) => JSON.stringify({ payloadType: 'application/vnd.in-toto+json', payload: Buffer.from(JSON.stringify(statement)).toString('base64'), signatures: [{ sig: 'fixture' }] });

test('offline manifest carries every required companion and refuses missing/misbound bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'release-inventories-'));
  try {
    const write = (name, bytes) => writeFileSync(join(dir, name), bytes);
    write('release-policy.json', '{}');
    const expected = new Map();
    for (const tool of ['cilock', 'jctl']) {
      const prefix = `${tool}-1.2.3-linux-amd64`;
      write(`${prefix}.tar.gz`, 'archive');
      const names = [];
      for (const step of ['source-git', 'build', 'sign']) {
        const name = `${prefix}.${step}.att.json`;
        names.push(name);
        const attestations = [];
        for (const kind of ['material', 'product']) {
          const predicate = { schema: inventoryType, kind, entries: [{ path: `${tool}/${step}`, fileDigest: 'a'.repeat(64) }] };
          const digest = hash(JSON.stringify(predicate));
          const companion = `${name}-${kind}-inventory.json`;
          names.push(companion);
          write(companion, envelope({ predicateType: inventoryType, subject: [{ name: `inventory:${kind}`, digest: { sha256: digest } }], predicate }));
          attestations.push({ type: `https://aflock.ai/attestations/${kind}/v0.3`, attestation: { inventory: { schema: inventoryType, kind, state: 'detached', digest, bytes: Buffer.byteLength(JSON.stringify(predicate)), fileCount: 1 } } });
        }
        write(name, envelope({ predicateType: 'https://aflock.ai/attestation-collection/v0.1', predicate: { name: step, attestations } }));
      }
      expected.set(`${prefix}.tar.gz`, names);
    }
    const run = () => spawnSync(process.execPath, [new URL('./publish-release.mjs', import.meta.url).pathname, '--dir', dir, '--version', 'v1.2.3', '--dry-run'], { encoding: 'utf8' });
    const good = run();
    assert.equal(good.status, 0, good.stderr);
    const manifest = JSON.parse(good.stdout.split('Manifest entry that WOULD be written:\n')[1]);
    for (const att of manifest.verification.attestations) {
      assert.deepEqual(att.envelopes.map((e) => e.file.replace('v1.2.3/', '')), expected.get(att.binary));
      for (const e of att.envelopes) {
        assert.equal(e.sha256, manifest.files.find((f) => `v1.2.3/${f.name}` === e.file).sha256);
        assert.ok(['source-git', 'build', 'sign'].includes(e.step), 'companions must not invent policy steps');
        if (e.kind) assert.equal(e.predicateType, inventoryType);
      }
    }
    const missing = 'jctl-1.2.3-linux-amd64.sign.att.json-material-inventory.json';
    rmSync(join(dir, missing));
    const absent = run();
    assert.notEqual(absent.status, 0, 'a required inventory must not silently disappear from offline verification');
    assert.match(absent.stderr, /missing.*inventory/i);
    write(missing, envelope({ predicateType: inventoryType, predicate: { kind: 'product' }, subject: [] }));
    const mismatched = run();
    assert.notEqual(mismatched.status, 0, 'an unrelated inventory is not a companion');
    assert.match(mismatched.stderr, /inventory.*(match|invalid)/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('companion transport binds exact raw predicate bytes and entry count, not claimed subjects', async (t) => {
  const raw = JSON.stringify({ schema: inventoryType, kind: 'material', entries: [{ path: 'original', fileDigest: 'a'.repeat(64) }] });
  // Non-ASCII is intentional: byte offsets and UTF-16 string offsets differ.
  const noncanonical = `{"entries" : [{"path":"\u00e9/\ud83d\ude80/}\\\"[,\\\\", "fileDigest":"${'a'.repeat(64)}"}],\n "kind":"material", "schema":"${inventoryType}" }`;
  const cases = [
    { name: 'canonical', ok: true },
    { name: 'same-size content tamper', body: raw.replace('original', 'modified') },
    { name: 'whitespace tamper', body: raw.replace('{', '{ ') },
    { name: 'same-size whitespace tamper', raw: raw.replace('{', '{ '), body: raw.replace('}', ' }') },
    { name: 'wrong byte count', ref: { bytes: Buffer.byteLength(raw) + 1 } },
    { name: 'string byte count', ref: { bytes: String(Buffer.byteLength(raw)) } },
    { name: 'missing byte count', ref: { bytes: undefined } },
    { name: 'over-limit byte count', ref: { bytes: 67108865 } },
    { name: 'wrong entry count', ref: { fileCount: 2 } },
    { name: 'string entry count', ref: { fileCount: '1' } },
    { name: 'missing entry count', ref: { fileCount: undefined } },
    { name: 'over-limit entry count', ref: { fileCount: 1000001 } },
    { name: 'empty entries', raw: JSON.stringify({ schema: inventoryType, kind: 'material', entries: [] }), ref: { fileCount: 0 } },
    { name: 'noncanonical UTF-8 predicate', raw: noncanonical, ok: true },
    { name: 'UTF-16 length is not byte count', raw: noncanonical, ref: { bytes: noncanonical.length } },
    { name: 'escaped predicate name', key: '"pred\\u0069cate"', ok: true },
    { name: 'escaped inventory field name', raw: raw.replace('"kind"', '"k\\u0069nd"'), ok: true },
    { name: 'paired Unicode escapes', raw: raw.replace('original', '\\ud83d\\ude80'), ok: true },
    { name: 'literal backslash Unicode text', raw: raw.replace('original', '\\\\ud800'), ok: true },
    { name: 'duplicate predicate', extra: `,"predicate":${raw}` },
    { name: 'escaped duplicate predicate', extra: `,"pred\\u0069cate":${raw}` },
    { name: 'duplicate nested key', raw: raw.replace('"kind":', '"kind":"product","k\\u0069nd":') },
    { name: 'duplicate entry key', raw: raw.replace('"path":', '"path":"other","p\\u0061th":') },
    { name: 'unpaired Unicode escape', raw: raw.replace('original', '\\ud800') },
    { name: 'invalid UTF-8', raw: Buffer.from(raw).map((b, i) => i === raw.indexOf('original') ? 0xff : b) },
    { name: 'trailing JSON value', suffix: '{}' },
    { name: 'excessive nesting', extra: `,"extension":${'['.repeat(129)}null${']'.repeat(129)}` },
  ];
  for (const c of cases) await t.test(c.name, () => {
    const dir = mkdtempSync(join(tmpdir(), 'release-raw-inventory-'));
    try {
      const write = (name, bytes) => writeFileSync(join(dir, name), bytes);
      const prefix = 'cilock-1.2.3-linux-amd64';
      const original = c.raw ?? raw;
      const ref = { schema: inventoryType, kind: 'material', state: 'detached', digest: hash(original), bytes: Buffer.byteLength(original), fileCount: 1, ...c.ref };
      const subject = JSON.stringify([{ name: 'inventory:material', digest: { sha256: ref.digest } }]);
      const payload = Buffer.concat([
        Buffer.from(`{ "subject":${subject}, "predicateType":"${inventoryType}", ${c.key ?? '"predicate"'} : \n`),
        Buffer.from(c.body ?? original), Buffer.from(` \t${c.extra ?? ''}}${c.suffix ?? ''}`),
      ]);
      write('release-policy.json', '{}');
      write(`${prefix}.tar.gz`, 'archive');
      write(`${prefix}.source-git.att.json`, envelope({ predicate: { attestations: [] } }));
      write(`${prefix}.build.att.json`, envelope({ predicate: { attestations: [{ type: 'https://aflock.ai/attestations/material/v0.3', attestation: { inventory: ref } }] } }));
      write(`${prefix}.build.att.json-material-inventory.json`, JSON.stringify({ payload: payload.toString('base64'), signatures: [{ sig: 'not-a-real-signature' }] }));
      const result = spawnSync(process.execPath, [new URL('./publish-release.mjs', import.meta.url).pathname, '--dir', dir, '--version', 'v1.2.3', '--dry-run'], { encoding: 'utf8' });
      if (c.ok) assert.equal(result.status, 0, result.stderr);
      else {
        assert.notEqual(result.status, 0, `${c.name} must fail with the original claimed subject intact`);
        assert.match(result.stderr, /inventory.*(match|invalid)|invalid inventory/i);
        assert.doesNotMatch(result.stdout, /Manifest entry that WOULD be written|Stage 3: UPLOAD/);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

test('inline and empty inventories need no companions; incomplete parents fail closed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'release-inline-'));
  try {
    const prefix = 'cilock-1.2.3-windows-amd64';
    writeFileSync(join(dir, 'release-policy.json'), '{}');
    writeFileSync(join(dir, `${prefix}.zip`), 'archive');
    for (const step of ['source-git', 'build']) {
      writeFileSync(join(dir, `${prefix}.${step}.att.json`), envelope({ predicate: { attestations: [{ type: 'https://aflock.ai/attestations/product/v0.3', attestation: { leaves: [], treeSize: 0 } }] } }));
    }
    const run = () => spawnSync(process.execPath, [new URL('./publish-release.mjs', import.meta.url).pathname, '--dir', dir, '--version', 'v1.2.3', '--dry-run'], { encoding: 'utf8' });
    const good = run();
    assert.equal(good.status, 0, good.stderr);
    const manifest = JSON.parse(good.stdout.split('Manifest entry that WOULD be written:\n')[1]);
    assert.equal(manifest.verification.attestations[0].envelopes.length, 2);
    rmSync(join(dir, `${prefix}.build.att.json`));
    assert.notEqual(run().status, 0, 'missing parent must fail before publication');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
