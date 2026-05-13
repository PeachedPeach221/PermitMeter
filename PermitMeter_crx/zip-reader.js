// PermitMeter — zip-reader.js
// Minimal ZIP reader. Extracts a single file by name from a ZIP ArrayBuffer.
// Reads compressedSize/method from the CENTRAL DIRECTORY (not local header),
// because when bit 3 of the general purpose flag is set the local header stores
// zeros and the real sizes live only in the central directory / data descriptor.

const ZipReader = (() => {
  const SIG_LOCAL   = 0x04034b50;
  const SIG_CENTRAL = 0x02014b50;
  const SIG_EOCD    = 0x06054b50;

  function read16(buf, off) {
    return buf[off] | (buf[off + 1] << 8);
  }

  function read32(buf, off) {
    return ((buf[off]) |
            (buf[off + 1] << 8) |
            (buf[off + 2] << 16) |
            (buf[off + 3] << 24)) >>> 0;
  }

  // Find the End-of-Central-Directory record (search backwards)
  function findEOCD(buf) {
    const limit = Math.max(0, buf.length - 65557);
    for (let i = buf.length - 22; i >= limit; i--) {
      if (read32(buf, i) === SIG_EOCD) return i;
    }
    return -1;
  }

  // Parse central directory → Map<filename, entry>
  function parseCentralDir(buf) {
    const eocdOff = findEOCD(buf);
    if (eocdOff < 0) throw new Error('ZIP: EOCD signature not found');

    const entriesCount = read16(buf, eocdOff + 10);
    const cdOffset     = read32(buf, eocdOff + 16);

    const entries = new Map();
    let off = cdOffset;

    for (let i = 0; i < entriesCount; i++) {
      if (off + 46 > buf.length) break;
      if (read32(buf, off) !== SIG_CENTRAL) break;

      const method           = read16(buf, off + 10);
      const compressedSize   = read32(buf, off + 20);
      const uncompressedSize = read32(buf, off + 24);
      const nameLen          = read16(buf, off + 28);
      const extraLen         = read16(buf, off + 30);
      const commentLen       = read16(buf, off + 32);
      const localHeaderOff   = read32(buf, off + 42);

      const name = new TextDecoder('utf-8').decode(buf.slice(off + 46, off + 46 + nameLen));

      entries.set(name, { localHeaderOff, compressedSize, uncompressedSize, method });
      off += 46 + nameLen + extraLen + commentLen;
    }

    return entries;
  }

  // Decompress raw deflate stream
  async function inflate(data) {
    const stream = new DecompressionStream('deflate-raw');
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();

    const writePromise = (async () => {
      await writer.write(data);
      await writer.close();
    })();

    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
    }
    await writePromise;

    const out = new Uint8Array(total);
    let pos = 0;
    for (const chunk of chunks) { out.set(chunk, pos); pos += chunk.length; }
    return out;
  }

  // Public: extract one file by name
  async function extractFile(zipBytes, targetName) {
    const buf = zipBytes instanceof Uint8Array ? zipBytes : new Uint8Array(zipBytes);

    const entries = parseCentralDir(buf);
    const entry = entries.get(targetName);
    if (!entry) return null;

    const { localHeaderOff, compressedSize, method } = entry;

    if (read32(buf, localHeaderOff) !== SIG_LOCAL) {
      throw new Error('ZIP: bad local file header signature');
    }

    // Skip past local header (30 fixed bytes + filename + extra)
    const localNameLen  = read16(buf, localHeaderOff + 26);
    const localExtraLen = read16(buf, localHeaderOff + 28);
    const dataOff = localHeaderOff + 30 + localNameLen + localExtraLen;

    // Always use compressedSize from central directory (handles streaming entries)
    const compData = buf.slice(dataOff, dataOff + compressedSize);

    if (method === 0) return compData;
    if (method === 8) return inflate(compData);
    throw new Error(`ZIP: unsupported compression method ${method}`);
  }

  return { extractFile };
})();
