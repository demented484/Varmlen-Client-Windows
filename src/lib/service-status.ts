export type ServiceStatusSnapshot = {
  phase: string;
};

export function serviceStatusLabel(
  state: ServiceStatusSnapshot | null,
  error: string | null,
): string {
  if (error || !state) return "Service unavailable";
  return state.phase.replaceAll("_", " ");
}
