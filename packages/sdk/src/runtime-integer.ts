/** Internal conversion at bounded JavaScript scheduling/allocation boundaries.
 * Protocol counters and opaque payload integers must never use this conversion. */
export function runtimeInteger(value: number | bigint, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value === 'bigint') {
    if (value < BigInt(minimum) || value > BigInt(maximum)) throw new RangeError('Integer exceeds runtime budget');
    return Number(value);
  }
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new RangeError('Invalid runtime integer');
  return value;
}

export function sameInteger(left: number | bigint, right: number | bigint): boolean {
  if ((typeof left === 'number' && !Number.isSafeInteger(left)) || (typeof right === 'number' && !Number.isSafeInteger(right))) return false;
  return BigInt(left) === BigInt(right);
}
