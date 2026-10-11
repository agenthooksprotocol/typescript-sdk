import assert from "node:assert/strict";
import test from "node:test";
import { parseJson } from "../dist/src/json.js";

test("lossless parser handles deeply nested arrays and objects without recursion", () => {
  for (const [open, close, key] of [["[", "]", 0], ['{"x":', "}", "x"]]) {
    let value = parseJson(open.repeat(10000) + "9007199254740993" + close.repeat(10000));
    for (let i = 0; i < 10000; i++) value = value[key];
    assert.equal(value, 9007199254740993n);
    assert.throws(() => parseJson(open.repeat(10000) + "null" + close.repeat(9999)), SyntaxError);
  }
});

test("lossless parser returns ordinary records and preserves prototype-named keys safely", () => {
  const text = '{"__proto__":{"polluted":true},"constructor":1,"nested":{"ok":true},"duplicate":0,"duplicate":2}';
  const value = parseJson(text);
  assert.deepEqual(value, JSON.parse(text));
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
  assert.equal(Object.getPrototypeOf(value.nested), Object.prototype);
  assert.equal(Object.hasOwn(value, "__proto__"), true);
  assert.equal(value.polluted, undefined);
});

test("lossless parser retains exact integer spellings and fractional values", () => {
  assert.deepEqual(parseJson('[9007199254740993,-9007199254740993,9007199254740993.0,9.007199254740993e15,90071992547409930e-1,1.25,1e-3,0e999999999]'),
    [9007199254740993n, -9007199254740993n, 9007199254740993n, 9007199254740993n, 9007199254740993n, 1.25, 0.001, 0]);
  assert.throws(() => parseJson("1e1000000000"), SyntaxError);
  assert.throws(() => parseJson("9007199254740993.1"), SyntaxError);
});

test("lossless parser rejects malformed syntax and accepts escaped strings", () => {
  for (const text of ["", " ", "[1,]", '{"x":1,}', "[1 2]", '{"x" 1}', "{x:1}", "true false", "01", "1.", "1e", "+1", "NaN", "Infinity", '"\\x"', '"\n"', '"unterminated', "\u00a0null", "[}", '{"x":}']) {
    assert.throws(() => parseJson(text), SyntaxError, text);
  }
  const text = '{"escaped\\\"key":"a\\n\\t\\u0062\\\\\\\"","array":[true,false,null,{},[]]}';
  assert.deepEqual(parseJson(text), JSON.parse(text));
});
