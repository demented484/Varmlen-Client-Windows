const REGIONAL_A = 0x1f1e6;
const REGIONAL_Z = 0x1f1ff;

/** Convert a Unicode regional-indicator flag to its lowercase ISO country code. */
export function countryCodeFromFlag(flag: string): string | null {
  const points = Array.from(flag.trim(), (char) => char.codePointAt(0) ?? 0);
  if (
    points.length !== 2 ||
    points.some((point) => point < REGIONAL_A || point > REGIONAL_Z)
  ) {
    return null;
  }
  return points
    .map((point) => String.fromCharCode(97 + point - REGIONAL_A))
    .join("");
}
