"""Pure network-watch rules (no database, no network) so they can be unit-tested on their own."""

SURGE_FACTOR = 5            # recent upload must be this many times the usual level...
SURGE_MIN_BPS = 1_000_000   # ...and at least 1 MB/s, so a quiet server's tiny numbers never trigger
SURGE_MIN_BUCKETS = 12      # an hour of 5-minute history before judging


def surge(recent_bps: float | None, buckets: list[float]) -> tuple[bool, float | None]:
    """(is_surge, usual level). The usual level is the p90 of earlier 5-minute averages."""
    if recent_bps is None or len(buckets) < SURGE_MIN_BUCKETS:
        return False, None
    s = sorted(buckets)
    usual = s[int(0.9 * (len(s) - 1))]
    return recent_bps >= max(SURGE_FACTOR * usual, SURGE_MIN_BPS), usual


class CentralWatch:
    """Tracks this server's own internet loss. Alerts cannot leave during an outage, so the report is made on
    recovery. A single failed check is ignored (one blip is not an outage)."""

    def __init__(self):
        self.fails = 0
        self.down_since: float | None = None

    def observe(self, ok: bool, now: float) -> int | None:
        """Minutes the outage lasted, once it has ended; otherwise None."""
        if not ok:
            self.fails += 1
            if self.down_since is None:
                self.down_since = now
            return None
        minutes = max(1, round((now - self.down_since) / 60)) if self.down_since is not None and self.fails >= 2 else None
        self.fails, self.down_since = 0, None
        return minutes
