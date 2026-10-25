import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../src/lib/analytics-consent.js', import.meta.url), 'utf8');
const key = 'sourceorrery.analytics.v1';
const now = 1_800_000_000_000;
const saved = (choice, at = now) => JSON.stringify({ version: 1, choice, at });

function browser({ value = null, blocked = false, gpc = false, dnt, hostname = 'sourceorrery.ai' } = {}) {
  const values = new Map(value === null ? [] : [[key, value]]);
  const listeners = new Map();
  const tags = [];
  const elements = new Map();
  let reloads = 0;
  const window = {
    location: { hostname, reload() { reloads++; } },
    localStorage: {
      getItem(name) { if (blocked) throw new Error('blocked'); return values.get(name) ?? null; },
      setItem(name, value) { if (blocked) throw new Error('blocked'); values.set(name, value); },
    },
    addEventListener(name, fn) { const list = listeners.get(name) ?? []; list.push(fn); listeners.set(name, list); },
    dispatchEvent(event) { for (const fn of listeners.get(event.type) ?? []) fn(event); },
  };
  const document = {
    head: { appendChild(tag) { tags.push(tag); elements.set(tag.id, tag); } },
    createElement(type) { assert.equal(type, 'script'); return { remove() { elements.delete(this.id); } }; },
    getElementById(id) { return elements.get(id); },
  };
  const context = vm.createContext({ window, document,
    navigator: { globalPrivacyControl: gpc, doNotTrack: dnt },
    Date: { now: () => now },
    CustomEvent: class { constructor(type) { this.type = type; } },
  });
  vm.runInContext(source, context);
  return { window, values, tags, api: window.sourceorreryAnalytics,
    reloads: () => reloads, rerun: () => vm.runInContext(source, context),
    event: (type, props = {}) => window.dispatchEvent({ type, ...props }),
  };
}

test('no decision or a stored refusal never creates a tracker or even a queue', () => {
  for (const value of [null, saved('denied')]) {
    const b = browser({ value });
    b.event('pageshow');
    b.event('storage', { key: 'unrelated' });
    assert.equal(b.tags.length, 0);
    assert.equal(b.window.clarity, undefined);
    b.api.choose('denied');
    assert.equal(b.tags.length, 0);
    assert.equal(b.reloads(), 0);
    assert.equal(JSON.parse(b.values.get(key)).choice, 'denied');
  }
});

test('acceptance injects the requested tag in head once, with advertising denied before load', () => {
  const b = browser();
  b.api.choose('granted');
  b.api.choose('granted');
  assert.equal(b.tags.length, 1);
  assert.equal(b.tags[0].src, 'https://www.clarity.ms/tag/z20sc8puam');
  assert.equal(b.tags[0].async, true);
  const first = b.window.clarity.q[0];
  assert.equal(first[0], 'consentv2');
  assert.equal(first[1].ad_Storage, 'denied');
  assert.equal(first[1].analytics_Storage, 'granted');
});

test('only current, valid, unexpired permission is remembered', () => {
  assert.equal(browser({ value: saved('granted') }).tags.length, 1);
  for (const value of ['invalid', '{}', saved('unknown'), saved('granted', now + 1), saved('granted', now - 180 * 86400000)]) {
    assert.equal(browser({ value }).tags.length, 0, value);
  }
  assert.equal(browser({ value: saved('denied', 0) }).api.choice(), 'denied');
});

test('GPC and Do Not Track override remembered permission and attempts to opt in', () => {
  for (const signals of [{ gpc: true }, { dnt: '1' }, { dnt: 'yes' }]) {
    const b = browser({ ...signals, value: saved('granted') });
    b.api.choose('granted');
    assert.equal(b.tags.length, 0);
    assert.equal(b.api.choice(), 'denied');
    assert.equal(JSON.parse(b.values.get(key)).choice, 'denied');
  }
});

test('revocation persists refusal, stops the collector and reloads into an unloaded page', () => {
  const b = browser({ value: saved('granted') });
  b.api.choose('denied');
  assert.equal(b.reloads(), 1);
  const calls = b.window.clarity.q;
  assert.equal(calls.at(-2)[0], 'consentv2');
  assert.equal(calls.at(-2)[1].analytics_Storage, 'denied');
  assert.equal(calls.at(-2)[1].ad_Storage, 'denied');
  assert.equal(calls.at(-1)[0], 'stop');
  assert.equal(browser({ value: b.values.get(key) }).tags.length, 0);
});

test('other-tab refusal and back/forward restoration also stop an active collector', () => {
  for (const event of ['storage', 'pageshow']) {
    const b = browser({ value: saved('granted') });
    b.values.set(key, saved('denied'));
    b.event(event, { key });
    assert.equal(b.api.choice(), 'denied');
    assert.equal(b.reloads(), 1);
  }
});

test('blocked storage and invalid choices default off; local previews never report visits', () => {
  const b = browser({ blocked: true });
  b.api.choose('invalid');
  b.api.choose('denied');
  assert.equal(b.tags.length, 0);
  assert.equal(browser({ value: saved('granted'), hostname: 'localhost' }).tags.length, 0);
});

test('re-executing the head controller does not duplicate loading or listeners', () => {
  const b = browser({ value: saved('granted') });
  b.rerun();
  assert.equal(b.tags.length, 1);
  b.api.choose('denied');
  assert.equal(b.reloads(), 1);
});
