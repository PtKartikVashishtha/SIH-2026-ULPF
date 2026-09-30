export function detectCharEncoding(buffer: Buffer): string {
  // Check ASCII
  let isAscii = true;
  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte !== undefined && byte > 127) {
      isAscii = false;
      break;
    }
  }
  if (isAscii) return "ASCII";

  // Check UTF-8 validity
  try {
    const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
    utf8Decoder.decode(buffer);
    return "UTF-8";
  } catch {
    // If not valid UTF-8, return ISO-8859-1 as standard fallback
    return "ISO-8859-1";
  }
}
