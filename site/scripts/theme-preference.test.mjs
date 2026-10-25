import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../src/lib/theme-preference.js', import.meta.url), 'utf8');
function browser({ stored = null, light = true, blocked = false } = {}) {
  const picker = { value: 'auto' };
  const root = { dataset: {} };
  let listener;
  const system = { matches: light, addEventListener(type, callback) { assert.equal(type, 'change'); listener = callback; } };
  const window = { matchMedia: () => system, localStorage: {
    getItem() { if (blocked) throw new Error('blocked'); return stored; },
    setItem(key, value) { if (blocked) throw new Error('blocked'); stored = value; },
  } };
  vm.runInNewContext(source, { window, document: { documentElement: root, querySelectorAll: () => [picker] } });
  return { api: window.sourceorreryTheme, root, picker, stored: () => stored, system(value) { system.matches = value; listener(); } };
}

test('restores an explicit theme and synchronises the native picker', () => {
  const b = browser({stored:'dark'});
  assert.equal(b.root.dataset.theme, 'dark');
  assert.equal(b.picker.value, 'dark');
  b.system(false);
  b.system(true);
  assert.equal(b.root.dataset.theme, 'dark');
  b.api.set('light');
  assert.equal(b.stored(), 'light');
  assert.equal(b.root.dataset.theme, 'light');
});

test('missing or invalid preferences use Auto and follow system changes', () => {
  for (const stored of [null, '', 'auto', 'invalid']) {
    const b = browser({ stored });
    assert.equal(b.picker.value, 'auto');
    assert.equal(b.root.dataset.theme, 'light');
    b.system(false);
    assert.equal(b.root.dataset.theme, 'dark');
    b.api.set('light');
    b.api.set('auto');
    assert.equal(b.stored(), '');
    assert.equal(b.root.dataset.theme, 'dark');
  }
});

test('denied storage permits this-page changes and Auto without exceptions', () => {
  const b = browser({blocked:true});
  b.api.set('dark');
  assert.equal(b.root.dataset.theme, 'dark');
  b.system(true);
  assert.equal(b.picker.value, 'dark');
  b.api.set('auto');
  assert.equal(b.root.dataset.theme, 'light');
  b.system(false);
  assert.equal(b.root.dataset.theme, 'dark');
});
