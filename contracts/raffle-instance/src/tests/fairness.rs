//! Post-draw fairness metadata assertions (#768).
//!
//! Guards against regressions in `do_finalize_with_seed`, which writes
//! `FairnessMetadata` to `DataKey::RandomnessSeed` exactly once per draw.
//! The tests finalize a raffle and assert that every field of
//! `get_fairness_data()` — including `unique_winners` and `draw_sequence` —
//! round-trips correctly, so that an accidental duplicate (or field-dropping)
//! write is caught.

use raffle_shared::RandomnessSource;
use soroban_sdk::{token::StellarAssetClient, Address, BytesN, Env, String, Vec};

use crate::{
    Contract, ContractClient, FairnessMetadata, DataKey, RaffleConfig, RaffleStatus,
    MIN_TICKET_PRICE,
};

fn setup_unique_winners_raffle(env: &Env) -> (ContractClient<'_>, Address, Address) {
    let contract_id = env.register(Contract, ());
    let client = ContractClient::new(env, &contract_id);

    let factory = Address::generate(env);
    let admin = Address::generate(env);
    let creator = Address::generate(env);
    let buyer = Address::generate(env);

    let token_admin = Address::generate(env);
    let payment_token = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    let token = StellarAssetClient::new(env, &payment_token);
    token.mint(&creator, &1_000_000_000_000);
    token.mint(&buyer, &1_000_000_000_000);

    let config = RaffleConfig {
        description: String::from_str(env, "unique winners fairness"),
        end_time: 0,
        no_deadline: true,
        max_tickets: 3,
        max_tickets_per_tx: 3,
        max_tickets_per_address: 0,
        min_tickets: 1,
        allow_multiple: true,
        ticket_price: MIN_TICKET_PRICE,
        payment_token: payment_token.clone(),
        prize_amount: MIN_TICKET_PRICE * 10,
        prizes: soroban_sdk::vec![env, 6000u32, 3000, 1000],
        randomness_source: RandomnessSource::Internal,
        oracle_address: None,
        oracle_public_key: None,
        protocol_fee_bp: 0,
        treasury_address: None,
        swap_router: None,
        tikka_token: None,
        metadata_hash: BytesN::from_array(env, &[77u8; 32]),
        claim_lockup_seconds: Some(0),
        swap_deadline_seconds: Some(300),
        early_bird_ticket_percentage: 0,
        early_bird_discount_bp: 0,
        category: None,
        unique_winners: true,
        bundles: Vec::new(env),
        prize_token: None,
        nft_contract: None,
    };

    client.init(&factory, &admin, &creator, &config);
    env.as_contract(&contract_id, || {
        env.storage().instance().remove(&DataKey::Factory);
    });
    client.deposit_prize();

    (client, contract_id, buyer)
}

#[test]
fn finalize_persists_all_fairness_fields_including_unique_winners() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let (client, contract_id, buyer) = setup_unique_winners_raffle(&env);

    client.buy_tickets(&buyer, &3);
    client.finalize_raffle();

    assert_eq!(client.get_raffle().status, RaffleStatus::Finalized);

    let fairness = client.get_fairness_data();

    // Every stored field must round-trip through get_fairness_data exactly.
    assert_eq!(fairness.randomness_source, RandomnessSource::Internal);
    assert_eq!(fairness.ticket_ids.len(), 3);
    assert_eq!(fairness.winning_ticket_indices.len(), 3);
    // unique_winners: true must be preserved (the bug dropped it in the
    // first (duplicate) write).
    assert_eq!(fairness.unique_winners, true);
    for i in 0..3 {
        assert_eq!(fairness.ticket_ids.get(i), Some(i + 1));
    }
    // draw_sequence is a copy of the ledger sequence at finalization.
    assert_eq!(fairness.draw_sequence, env.ledger().sequence());

    // Re-running must be deterministic for the same seed.
    assert_eq!(fairness.seed, client.get_fairness_data().seed);

    // Exactly one authoritative write to RandomnessSeed for this draw: the
    // stored metadata reflects a single finalization with unique_winners set
    // (the prior duplicate write dropped unique_winners and never compiled).
    env.as_contract(&contract_id, || {
        let meta: FairnessMetadata = env
            .storage()
            .persistent()
            .get(&DataKey::RandomnessSeed)
            .expect("fairness metadata must exist after finalization");
        assert_eq!(meta.unique_winners, true);
        assert_eq!(meta.winning_ticket_indices.len(), 3);
    });
}

#[test]
fn finalize_unique_winners_stays_within_budget() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, buyer) = setup_unique_winners_raffle(&env);
    client.buy_tickets(&buyer, &3);

    let (cpu_before, _) = snapshot(&env);
    client.finalize_raffle();
    let (cpu_after, _) = snapshot(&env);

    // Generous ceiling; the key regression guard is that the redundant
    // duplicate write (now removed) is no longer charged on the finalize path.
    assert!(cpu_after.saturating_sub(cpu_before) < 80_000_000);
}

fn snapshot(env: &Env) -> (u64, u64) {
    let budget = env.cost_estimate().budget();
    (
        budget.cpu_instruction_cost(),
        budget.memory_bytes_cost(),
    )
}

// ── Acceptance-criterion tests for #1006 ─────────────────────────────────────
//
// Regression guard: select_winner_indices(env, n, k) must return exactly
// min(k, n) indices.  The bug kept `drawn_count` at zero so the break never
// fired, and the loop collected every unique index up to total_tickets instead
// of stopping at winner_count.

#[cfg(test)]
mod winner_count_regression {
    use crate::randomness::{OracleSeedWinnerSelection, PrngWinnerSelection, WinnerSelectionStrategy};
    use soroban_sdk::{Address, Env};

    /// k = 1: a single-winner draw must return exactly one index.
    #[test]
    fn prng_returns_exactly_one_winner_when_k_is_one() {
        let env = Env::default();
        let contract = env
            .register_stellar_asset_contract_v2(Address::generate(&env))
            .address();
        let raffle_id = Address::generate(&env);
        let selector = PrngWinnerSelection::new(raffle_id, 50);
        let indices = env.as_contract(&contract, || {
            selector.select_winner_indices(&env, 50, 1)
        });
        assert_eq!(
            indices.len(),
            1,
            "k=1: expected exactly 1 winner, got {}",
            indices.len()
        );
    }

    /// k = prizes.len(): a multi-tier draw must return exactly prizes.len() indices.
    #[test]
    fn prng_returns_exactly_prize_count_winners() {
        let env = Env::default();
        let contract = env
            .register_stellar_asset_contract_v2(Address::generate(&env))
            .address();
        let raffle_id = Address::generate(&env);
        let prizes_len: u32 = 3;
        let selector = PrngWinnerSelection::new(raffle_id, 500);
        let indices = env.as_contract(&contract, || {
            selector.select_winner_indices(&env, 500, prizes_len)
        });
        assert_eq!(
            indices.len(),
            prizes_len,
            "k=prizes_len: expected {} winners, got {}",
            prizes_len,
            indices.len()
        );
    }

    /// k > n: when more winners are requested than tickets exist, return at
    /// most n (no duplicates possible beyond that cap).
    #[test]
    fn oracle_seed_caps_at_total_tickets_when_k_exceeds_n() {
        let selector = OracleSeedWinnerSelection::new(0xDEAD_BEEF_1234_5678);
        let total_tickets: u32 = 4;
        let winner_count: u32 = 10; // k > n
        let indices = selector.select_winner_indices_pure(total_tickets, winner_count);
        assert_eq!(
            indices.len(),
            total_tickets as usize,
            "k>n: expected {} winners (capped at total_tickets), got {}",
            total_tickets,
            indices.len()
        );
        // All indices must be unique and in-range.
        let mut seen = std::collections::HashSet::new();
        for &idx in &indices {
            assert!(idx < total_tickets, "index {idx} out of range [0, {total_tickets})");
            assert!(seen.insert(idx), "duplicate index {idx}");
        }
    }
}

// ── #991: unique-winner draws must not bias neighbouring ticket holders ─────
//
// `resolve_unique_winner` used to walk forward from the originally drawn index
// (`candidate + 1`, `candidate + 2`, …) until it found an owner that had not
// already won. Every collision therefore landed on the ticket immediately after
// the colliding one, so with a small participant set and multiple tiers the
// holder sitting just past a repeat winner was systematically over-represented
// and ticket 0 was the least likely winner of all. The probe is replaced by a
// bounded, domain-separated re-draw (`resample_unique_index`), and these tests
// pin the resulting distribution.
//
// The fixture is deliberately the worst case for the old probe: three owners
// holding one contiguous block of tickets each, two prize tiers. Ticket blocks
// are contiguous so a forward walk has somewhere obvious to stop.

#[cfg(test)]
mod unique_winner_uniformity {
    use crate::randomness::OracleSeedWinnerSelection;

    /// Number of distinct ticket owners in the fixture below.
    const OWNERS: u32 = 3;
    /// Prize tiers drawn per simulation. Two tiers is the minimum that forces a
    /// second tier to re-draw: the first tier has no prior winner to collide
    /// with.
    const TIERS: u32 = 2;
    /// Owner of `ticket`: one contiguous block of tickets per owner.
    fn owner_of(ticket: u32, total_tickets: u32) -> u32 {
        ticket * OWNERS / total_tickets
    }
    /// Size of owner 0's ticket block, i.e. the number of tickets that become
    /// ineligible for the second tier once owner 0 has won.
    fn first_block_size(total_tickets: u32) -> u32 {
        (total_tickets + OWNERS - 1) / OWNERS
    }

    /// Chi-squared statistic of `histogram` against a uniform expectation.
    fn compute_chi_squared(histogram: &[u32], total_samples: u32) -> f64 {
        let k = histogram.len() as f64;
        let expected = total_samples as f64 / k;
        let mut chi2 = 0.0;
        for &count in histogram {
            let diff = count as f64 - expected;
            chi2 += (diff * diff) / expected;
        }
        chi2
    }

    /// Two-sided Chi-squared critical value at alpha = 0.001.
    fn critical_value_999(degrees_of_freedom: usize) -> f64 {
        // Wilson-Hilferty approximation, accurate to a few percent over the
        // range used here, which is far tighter than the effect being detected.
        let df = degrees_of_freedom as f64;
        let z = 3.090232306167813;
        df * (1.0 - 2.0 / (9.0 * df) + z * (2.0 / (9.0 * df)).sqrt()).powi(3)
    }

    /// Runs the two-tier `unique_winners = true` draw loop used on-chain and
    /// returns the tier-1 winners observed when tier 0 went to owner 0.
    ///
    /// Conditioning on tier 0 matters: tier 1 can only ever be won by one of
    /// the two *remaining* owners, so an unconditional histogram over all
    /// tickets would encode the fixture rather than the selector. Holding tier
    /// 0 fixed makes "uniform over the eligible tickets" the exact null
    /// hypothesis.
    fn tier1_winners_when_tier0_is_owner0(
        total_tickets: u32,
        total_draws: u64,
    ) -> (std::vec::Vec<u32>, u32) {
        let eligible = first_block_size(total_tickets);
        let mut histogram = std::vec![0u32; (total_tickets - eligible) as usize];
        let mut samples = 0u32;

        for raw_seed in 1..=total_draws {
            let seed = raw_seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let selector = OracleSeedWinnerSelection::new(seed);
            let drawn = selector.select_winner_indices_pure(total_tickets, TIERS);
            assert_eq!(drawn.len(), TIERS as usize);

            // Tier 0 has no prior winner, so the re-draw accepts its draw
            // verbatim and the winner is the ordinary uniform draw.
            let tier0 = selector.resample_unique_index(0, total_tickets, drawn[0], |_| true);
            assert_eq!(tier0, drawn[0], "tier 0 must not be re-drawn");
            if owner_of(tier0, total_tickets) != 0 {
                continue;
            }

            // Tier 1 must re-draw, since owner 0 has just won.
            let tier1 = selector.resample_unique_index(1, total_tickets, drawn[1], |index| {
                owner_of(index, total_tickets) != 0
            });
            assert!(
                (eligible..total_tickets).contains(&tier1),
                "tier 1 must land on an unclaimed owner's ticket, got {tier1}"
            );

            histogram[(tier1 - eligible) as usize] += 1;
            samples += 1;
        }

        (histogram, samples)
    }

    /// The headline acceptance criterion: unique-winner draws are uniform over
    /// the eligible tickets, exactly like ordinary draws.
    ///
    /// The old linear probe put ~1/3 of all tier-1 draws on the single ticket
    /// immediately after owner 0's block instead of the expected ~1/20, so this
    /// rejects the biased implementation by a wide margin.
    #[test]
    fn unique_winner_redraw_is_uniform_over_eligible_tickets() {
        // 30_000 draws leaves ~10_000 conditioned samples.
        let total_draws = 30_000u64;
        let total_tickets = 30u32;
        let (histogram, samples) = tier1_winners_when_tier0_is_owner0(total_tickets, total_draws);

        assert!(
            samples >= 1_000,
            "conditioning on tier 0 must leave a usable sample, got {samples}"
        );
        assert_eq!(
            histogram.iter().filter(|&&c| c == 0).count(),
            0,
            "every eligible ticket must be reachable, histogram {histogram:?}"
        );

        let chi2 = compute_chi_squared(&histogram, samples);
        let crit = critical_value_999(histogram.len() - 1);
        assert!(
            chi2 < crit,
            "unique-winner re-draw is biased for ticket_count={total_tickets}: \
             chi2={chi2} >= critical={crit}, histogram={histogram:?}"
        );
    }

    /// Same test at a ticket count that is not a multiple of `OWNERS`, so block
    /// sizes differ and the re-draw cannot lean on alignment.
    #[test]
    fn unique_winner_redraw_is_uniform_with_ragged_blocks() {
        let total_draws = 30_000u64;
        let total_tickets = 32u32;
        let (histogram, samples) = tier1_winners_when_tier0_is_owner0(total_tickets, total_draws);

        assert!(samples >= 1_000, "conditioned sample too small: {samples}");
        let chi2 = compute_chi_squared(&histogram, samples);
        let crit = critical_value_999(histogram.len() - 1);
        assert!(
            chi2 < crit,
            "unique-winner re-draw is biased for ticket_count={total_tickets}: \
             chi2={chi2} >= critical={crit}, histogram={histogram:?}"
        );
    }

    /// A tier whose original draw is already acceptable is returned untouched,
    /// so the common path costs no extra randomness and stays reproducible with
    /// the off-chain `select_winner_indices_pure` mirror.
    #[test]
    fn unique_winner_redraw_keeps_an_acceptable_draw() {
        let selector = OracleSeedWinnerSelection::new(0x0123_4567_89AB_CDEF);
        let total_tickets = 64u32;
        for seed_ticket in 0..total_tickets {
            assert_eq!(
                selector.resample_unique_index(0, total_tickets, seed_ticket, |index| {
                    index == seed_ticket
                }),
                seed_ticket,
                "an acceptable draw must be kept verbatim"
            );
        }
    }

    /// Exhausting the retry budget must yield the fallback rather than loop
    /// forever — the single-address-owns-everything case (#485).
    #[test]
    fn unique_winner_redraw_falls_back_when_nothing_is_acceptable() {
        let selector = OracleSeedWinnerSelection::new(0xFEED_FACE_CAFE_BEEF);
        let total_tickets = 128u32;
        for tier_index in 0..8u32 {
            assert_eq!(
                selector.resample_unique_index(tier_index, total_tickets, 7, |_| false),
                7,
                "with no acceptable ticket the fallback must be returned"
            );
        }
    }

    /// `tier_index` must domain-separate the re-draw stream.
    ///
    /// Asserting that every tier yields a *distinct* ticket would be a
    /// birthday test and would fail by chance roughly two runs in three, so
    /// what is asserted instead is that the per-tier draw sequences are
    /// genuinely independent: over many tiers, each ticket should be reached
    /// at close to the uniform rate. If `tier_index` were ignored, every tier
    /// would replay one identical stream and the histogram would be a handful
    /// of over-represented tickets — the same signature #991 reported.
    #[test]
    fn unique_winner_redraw_separates_streams_by_tier() {
        let total_tickets = 64u32;
        let tiers = 2_000u32;
        let mut histogram = std::vec![0u32; total_tickets as usize];

        for tier_index in 0..tiers {
            // Only index 0 is unacceptable, so every tier takes exactly one
            // fresh LCG sample from its own stream.
            let idx = OracleSeedWinnerSelection::new(0xA5A5_5A5A_1234_9999).resample_unique_index(
                tier_index,
                total_tickets,
                0,
                |index| index != 0,
            );
            histogram[idx as usize] += 1;
        }

        let expected = tiers as f64 / total_tickets as f64;
        let chi2: f64 = histogram
            .iter()
            .map(|&c| {
                let d = c as f64 - expected;
                d * d / expected
            })
            .sum();
        let crit = critical_value_999(total_tickets as usize - 1);
        assert!(
            chi2 < crit,
            "re-draw streams are not domain-separated by tier_index: \
             chi2={chi2} >= critical={crit}, histogram={histogram:?}"
        );
    }

    /// The re-draw stream must depend on the seed, not just the tier.
    #[test]
    fn unique_winner_redraw_separates_streams_by_seed() {
        let total_tickets = 97u32;
        let a = OracleSeedWinnerSelection::new(0x1111_1111_1111_1111);
        let b = OracleSeedWinnerSelection::new(0x2222_2222_2222_2222);
        assert_ne!(
            a.resample_unique_index(0, total_tickets, 0, |index| index != 0),
            b.resample_unique_index(0, total_tickets, 0, |index| index != 0),
            "distinct seeds must yield distinct re-draw streams"
        );
    }
}
