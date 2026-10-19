/** Shared publication/intake horizon: allow 14 days for delays and timezone differences. */
export const PERIOD_END_FUTURE_HORIZON_DAYS = 14;

/** Reject nonexistent calendar dates and reports beyond the existing intake horizon. */
export function isPeriodEndTooFarInFuture(periodEnd: string, now: Date = new Date()): boolean {
  const parsed = new Date(`${periodEnd}T00:00:00Z`);
  const t = parsed.getTime();
  if (Number.isNaN(t) || parsed.toISOString().slice(0, 10) !== periodEnd) return true;
  return t - now.getTime() > PERIOD_END_FUTURE_HORIZON_DAYS * 24 * 60 * 60 * 1000;
}
