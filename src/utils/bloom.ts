import crypto from "node:crypto";

export class BloomFilter {
  private bits: Buffer;
  private readonly m: number; // number of bits
  private readonly k: number; // number of hash functions

  constructor(
    m: number = Number(process.env.BLOOM_M) || 8_000_000,
    k: number = Number(process.env.BLOOM_K) || 7,
    bits?: Buffer,
  ) {
    this.m = m;
    this.k = k;
    // Lazy allocation: avoid allocating large buffers at startup in constrained environments.
    if (bits) {
      this.bits = bits;
    } else {
      this.bits = Buffer.alloc(0);
    }
  }

  private bitIndex(hashVal: number): number {
    return Math.abs(hashVal) % this.m;
  }

  private ensureAllocated() {
    if (this.bits.length === 0) {
      const byteLen = Math.ceil(this.m / 8);
      this.bits = Buffer.alloc(byteLen, 0);
    }
  }

  private setBit(pos: number) {
    this.ensureAllocated();
    const byte = Math.floor(pos / 8);
    const off = pos % 8;
    this.bits[byte] = this.bits[byte] | (1 << off);
  }

  private getBit(pos: number): boolean {
    if (this.bits.length === 0) return false;
    const byte = Math.floor(pos / 8);
    const off = pos % 8;
    return (this.bits[byte] & (1 << off)) !== 0;
  }

  add(item: string) {
    for (let i = 0; i < this.k; i++) {
      const h = this.hash(item, i);
      const pos = this.bitIndex(h);
      this.setBit(pos);
    }
  }

  has(item: string): boolean {
    for (let i = 0; i < this.k; i++) {
      const h = this.hash(item, i);
      const pos = this.bitIndex(h);
      if (!this.getBit(pos)) return false;
    }
    return true;
  }

  private hash(item: string, seed: number): number {
    const h = crypto.createHash("sha256");
    h.update(String(seed));
    h.update("|");
    h.update(item);
    const digest = h.digest();
    // use 4 bytes chunks to produce a 32-bit int; combine with seed
    return digest.readInt32BE(0) ^ (seed * 0x9e3779b1);
  }

  serialize(): string {
    return this.bits.toString("base64");
  }

  static deserialize(
    b64: string,
    m: number = 8_000_000,
    k: number = 7,
  ): BloomFilter {
    const buf = Buffer.from(b64, "base64");
    return new BloomFilter(m, k, buf);
  }
}
