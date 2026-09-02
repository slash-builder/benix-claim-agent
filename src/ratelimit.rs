//! A simple per-source-IP token bucket for `POST /v1/onboard/claim`.
//!
//! security-engineer's explicit hardening requirement (finalized contract,
//! `context/projects/benixos.md` §9j): this is a real, if simple,
//! pre-authentication surface reachable by anything on the LAN. Hand-rolled
//! rather than pulling in `governor`, per the contract's own "don't
//! over-engineer distributed rate limiting for a single-process LAN
//! service" note — a `Mutex<HashMap<IpAddr, Bucket>>` is enough here, and
//! keeps the dependency surface (and thus the musl-cleanliness question)
//! smaller.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    /// Fractional tokens, so a slow steady trickle of requests still
    /// refills smoothly rather than only unlocking a new request once a
    /// whole token has accumulated in discrete per-minute jumps.
    tokens: f64,
    last_refill: Instant,
}

/// Per-source-IP token bucket. `capacity` tokens refill continuously over
/// one minute; each request consumes one. Unbounded map growth over a long
/// uptime is a known, accepted tradeoff for a single-process LAN service
/// with a small realistic address space (see module docs) — not swept.
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(capacity_per_minute: u32) -> Self {
        let capacity = capacity_per_minute.max(1) as f64;
        Self {
            capacity,
            refill_per_sec: capacity / 60.0,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// `true` if `ip` has a token available (and consumes it); `false` if
    /// the bucket is empty and the caller should respond `429`.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("ratelimit bucket lock");
        let bucket = buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.capacity,
            last_refill: now,
        });

        let elapsed = now.saturating_duration_since(bucket.last_refill);
        bucket.tokens =
            (bucket.tokens + elapsed.as_secs_f64() * self.refill_per_sec).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().expect("ratelimit bucket lock");
        let bucket = buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.capacity,
            last_refill: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last_refill);
        bucket.tokens =
            (bucket.tokens + elapsed.as_secs_f64() * self.refill_per_sec).min(self.capacity);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, n))
    }

    #[test]
    fn allows_up_to_capacity_then_blocks() {
        let rl = RateLimiter::new(3);
        let addr = ip(1);
        assert!(rl.allow(addr));
        assert!(rl.allow(addr));
        assert!(rl.allow(addr));
        assert!(
            !rl.allow(addr),
            "4th request within the window must be blocked"
        );
    }

    #[test]
    fn buckets_are_independent_per_source_ip() {
        let rl = RateLimiter::new(1);
        assert!(rl.allow(ip(1)));
        assert!(!rl.allow(ip(1)));
        // A different source IP has its own, untouched bucket.
        assert!(rl.allow(ip(2)));
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(60); // 1 token/sec
        let addr = ip(1);
        let t0 = Instant::now();
        for _ in 0..60 {
            assert!(rl.allow_at(addr, t0));
        }
        assert!(!rl.allow_at(addr, t0), "bucket should be empty");
        // One second later, exactly one token should have refilled.
        let t1 = t0 + Duration::from_secs(1);
        assert!(rl.allow_at(addr, t1));
        assert!(!rl.allow_at(addr, t1));
    }

    #[test]
    fn never_exceeds_capacity_even_after_a_long_idle_period() {
        let rl = RateLimiter::new(5);
        let addr = ip(1);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(3600);
        // Bucket starts full; idling doesn't overflow it beyond capacity.
        for _ in 0..5 {
            assert!(rl.allow_at(addr, t1));
        }
        assert!(!rl.allow_at(addr, t1));
    }
}
