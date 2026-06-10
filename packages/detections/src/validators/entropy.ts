// Shannon entropy — used to distinguish random secrets from low-entropy words
export function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] ?? 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// A string with entropy >= 3.5 across a 20+ char run is likely a secret
export function isHighEntropy(value: string, threshold = 3.5): boolean {
  return value.length >= 20 && shannonEntropy(value) >= threshold;
}
