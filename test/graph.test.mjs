import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_POSITIONS, NODE_DETAILS, clampPosition, demoPath } from '../public/graph.mjs';
test('teaching map includes an explanation for every system node', () => { for (const id of Object.keys(DEFAULT_POSITIONS)) assert.ok(NODE_DETAILS[id]?.what && NODE_DETAILS[id]?.security); });
test('drag positions stay inside the graph viewport', () => { assert.deepEqual(clampPosition([-20, 700]), [52, 508]); assert.deepEqual(clampPosition([400, 300]), [400, 300]); });
test('walkthrough paths progress through the boundary to evidence', () => { assert.deepEqual(demoPath(0), ['agent', 'proxy']); assert.deepEqual(demoPath(1), ['proxy', 'weather']); assert.deepEqual(demoPath(2), ['proxy', 'ledger']); });
test('denied walkthroughs stop at the proxy instead of reaching a tool', () => { assert.deepEqual(demoPath(0, false), ['agent', 'proxy']); assert.deepEqual(demoPath(1, false), ['proxy']); assert.deepEqual(demoPath(2, false), ['proxy', 'ledger']); });
