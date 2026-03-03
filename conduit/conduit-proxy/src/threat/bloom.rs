//! Bloom filter for threat feed domain matching.
//!
//! Wraps the `bloomfilter` crate with Redis persistence and atomic swap
//! for hot-reloading during feed refresh.

use bloomfilter::Bloom;
use deadpool_redis::Pool;
use redis::AsyncCommands;
use tracing::{debug, error, warn};

/// Create a new bloom filter with the given capacity and false-positive rate.
pub fn new_bloom(capacity: usize, fp_rate: f64) -> Bloom<str> {
    Bloom::new_for_fp_rate(capacity, fp_rate)
}

/// Check if a domain is in the bloom filter.
pub fn contains(bloom: &Bloom<str>, domain: &str) -> bool {
    bloom.check(domain)
}

/// Insert a domain into the bloom filter.
pub fn insert(bloom: &mut Bloom<str>, domain: &str) {
    bloom.set(domain);
}

/// Load a bloom filter bitmap from Redis.
/// Returns None if no stored filter exists.
pub async fn load_from_redis(pool: &Pool, _capacity: usize, _fp_rate: f64) -> Option<Bloom<str>> {
    let mut conn = pool.get().await.ok()?;
    let data: Option<Vec<u8>> = conn
        .get(conduit_common::redis::keys::THREAT_BLOOM)
        .await
        .ok()?;

    let data = data?;
    if data.is_empty() {
        return None;
    }

    match serde_json::from_slice::<BloomSerde>(&data) {
        Ok(stored) => {
            let bloom = Bloom::from_existing(
                &stored.bitmap,
                stored.bitmap_bits,
                stored.k_num,
                [(stored.sip0, stored.sip1), (stored.sip2, stored.sip3)],
            );
            debug!(entries = stored.entry_count, "Loaded bloom filter from Redis");
            Some(bloom)
        }
        Err(e) => {
            warn!("Failed to deserialize bloom filter from Redis: {e}");
            None
        }
    }
}

/// Save the bloom filter bitmap to Redis for persistence across restarts.
pub async fn save_to_redis(pool: &Pool, bloom: &Bloom<str>, entry_count: u64) {
    let Ok(mut conn) = pool.get().await else {
        error!("Failed to get Redis connection for bloom save");
        return;
    };

    let serde = BloomSerde {
        bitmap: bloom.bitmap(),
        bitmap_bits: bloom.number_of_bits(),
        k_num: bloom.number_of_hash_functions(),
        sip0: bloom.sip_keys()[0].0,
        sip1: bloom.sip_keys()[0].1,
        sip2: bloom.sip_keys()[1].0,
        sip3: bloom.sip_keys()[1].1,
        entry_count,
    };

    match serde_json::to_vec(&serde) {
        Ok(data) => {
            let _: Result<(), _> = conn
                .set(conduit_common::redis::keys::THREAT_BLOOM, data)
                .await;

            // Update metadata
            let _: Result<(), _> = conn
                .hset_multiple(
                    conduit_common::redis::keys::THREAT_BLOOM_META,
                    &[
                        ("entry_count", entry_count.to_string()),
                        ("updated_at", chrono::Utc::now().to_rfc3339()),
                    ],
                )
                .await;

            debug!(entry_count, "Saved bloom filter to Redis");
        }
        Err(e) => {
            error!("Failed to serialize bloom filter: {e}");
        }
    }
}

/// Serializable representation of a bloom filter.
#[derive(serde::Serialize, serde::Deserialize)]
struct BloomSerde {
    bitmap: Vec<u8>,
    bitmap_bits: u64,
    k_num: u32,
    sip0: u64,
    sip1: u64,
    sip2: u64,
    sip3: u64,
    entry_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_bloom_operations() {
        let mut bloom = new_bloom(1000, 0.01);
        assert!(!contains(&bloom, "evil.com"));

        insert(&mut bloom, "evil.com");
        assert!(contains(&bloom, "evil.com"));
        assert!(!contains(&bloom, "good.com"));
    }

    #[test]
    fn bloom_false_positive_rate() {
        let mut bloom = new_bloom(10000, 0.001);
        for i in 0..1000 {
            insert(&mut bloom, &format!("bad{i}.com"));
        }

        // Check FP rate with 10000 non-inserted domains
        let mut fps = 0;
        for i in 0..10000 {
            if contains(&bloom, &format!("good{i}.example.org")) {
                fps += 1;
            }
        }

        // At 0.1% FP rate, expect ~10 FPs out of 10000, allow some margin
        assert!(fps < 50, "Too many false positives: {fps}");
    }
}
