import type { EditorChoice } from "./api";

/** Preserve provider/core values that are newer than the local catalogue
 * without silently changing them or forcing an invalid default. */
export function includeCurrentOption(
  options: EditorChoice[],
  current: string,
): EditorChoice[] {
  if (!current || options.some((option) => option.value === current)) {
    return options;
  }
  return [...options, { value: current, label: current }];
}
