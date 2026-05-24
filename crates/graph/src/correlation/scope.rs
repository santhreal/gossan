//! Shared scoping + distinct-pair primitive for correlation rules.
//!
//! Every "chain" rule does the same two things: (1) cluster findings by
//! a normalised scope (host, or registrable parent), and (2) fire only
//! when *two independent* findings in one scope match two predicates  - 
//! never when a single finding satisfies both (that is one finding
//! already reported by its own scanner, not a correlation).
//!
//! Step (2)  -  the "distinct-pair / self-chain guard"  -  was hand-rolled
//! in five rules with subtly different `ptr::eq` loops; several shipped
//! without it at all and produced duplicate Criticals. This module is
//! the single audited, property-fuzzed implementation. It is generic so
//! the guard's invariants are exhaustively tested with cheap values and
//! then reused verbatim for `Finding`.

use std::collections::HashMap;
use std::hash::Hash;

use secfinding::Finding;

use crate::correlation::utils::normalize_host;

/// Per-host clustering key (the granularity most rules use).
pub(crate) fn host_scope(f: &Finding) -> String {
    normalize_host(f.target())
}

/// Registrable-parent clustering key (coarser "same blast radius"
/// grouping  -  used by the SSRF→internal-service chain so an SSRF and
/// an exposed datastore on different subdomains of one registrable
/// domain still correlate). Built on the canonical
/// `gossan_core::domain` so it is case/IDN/trailing-dot insensitive
/// and consistent with [`host_scope`].
///
/// Note: rules whose scope is *not* a flat registrable-parent
/// partition deliberately do NOT use this. `wildcard_takeover` keys on
/// the wildcard's own level (`*.api.example.com` ⇒ `api.example.com`,
/// matched by hierarchical `ends_with(".{p}")` suffix containment);
/// collapsing that to the registrable parent would re-introduce the
/// cross-level false positive that rule was hardened against.
pub(crate) fn parent_scope(f: &Finding) -> String {
    gossan_core::domain::parent_domain(&normalize_host(f.target()))
}

/// Group borrowed items by an arbitrary scope key, preserving input
/// order within each bucket.
pub(crate) fn group_by<'a, T, K>(
    items: &'a [T],
    key: impl Fn(&T) -> K,
) -> HashMap<K, Vec<&'a T>>
where
    K: Eq + Hash,
{
    let mut m: HashMap<K, Vec<&'a T>> = HashMap::new();
    for it in items {
        m.entry(key(it)).or_default().push(it);
    }
    m
}

/// The self-chain guard  -  single source of truth.
///
/// Returns a witnessing pair `(a, b)` where `pred_a(a)` and `pred_b(b)`
/// and `a`/`b` are **distinct objects** (pointer identity, not value
/// equality  -  two findings with identical fields are still two
/// findings). Returns `None` when the only way to satisfy both
/// predicates is a single item satisfying both  -  that is not a
/// correlation.
///
/// Generic over `T` purely so the invariants below can be fuzzed with
/// trivial values; the rules instantiate it at `T = Finding`.
///
/// Invariants (see tests):
/// * never returns `(x, x)` for the same object;
/// * returns `Some` iff `∃ i ≠ j` with `pred_a(items[i]) ∧
///   pred_b(items[j])` (matches a brute-force oracle);
/// * the *existence* of a result is invariant under input permutation;
/// * any returned pair actually satisfies the predicates.
pub(crate) fn distinct_pair<'a, T>(
    items: &[&'a T],
    pred_a: impl Fn(&T) -> bool,
    pred_b: impl Fn(&T) -> bool,
) -> Option<(&'a T, &'a T)> {
    // O(n) instead of the original nested pred_a×pred_b scan. Each
    // correlation rule calls this once per host/parent group; on a
    // large scan a single host can carry thousands of findings, so the
    // old O(n²) was n² *per group per rule* across ~6 rules. The
    // existence/soundness contract is unchanged and is proven against
    // the brute-force oracle proptest below.
    let a = items.iter().copied().find(|x| pred_a(x))?;
    let b = items.iter().copied().find(|x| pred_b(x))?;
    if !std::ptr::eq(a, b) {
        return Some((a, b));
    }
    // `a` and `b` are the *same* object (it satisfies both predicates).
    // That alone is not a pair  -  find a distinct partner: another
    // pred_a item that isn't `b`, or another pred_b item that isn't
    // `a`. If neither exists the only satisfying assignment is a single
    // object, so there is genuinely no distinct pair.
    if let Some(a2) = items
        .iter()
        .copied()
        .find(|x| !std::ptr::eq(*x, b) && pred_a(x))
    {
        return Some((a2, b));
    }
    if let Some(b2) = items
        .iter()
        .copied()
        .find(|x| !std::ptr::eq(*x, a) && pred_b(x))
    {
        return Some((a, b2));
    }
    None
}

/// Convenience: does a distinct satisfying pair exist in this group?
pub(crate) fn has_distinct_pair<T>(
    items: &[&T],
    pred_a: impl Fn(&T) -> bool,
    pred_b: impl Fn(&T) -> bool,
) -> bool {
    distinct_pair(items, pred_a, pred_b).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn refs<T>(v: &[T]) -> Vec<&T> {
        v.iter().collect()
    }

    /// The exact self-chain bug, distilled: one item that satisfies
    /// BOTH predicates is not a pair.
    #[test]
    fn single_item_satisfying_both_is_not_a_pair() {
        let v = [7u32];
        let g = refs(&v);
        assert_eq!(distinct_pair(&g, |_| true, |_| true), None);
        assert!(!has_distinct_pair(&g, |&x| x == 7, |&x| x == 7));
    }

    #[test]
    fn two_distinct_items_one_each_is_a_pair() {
        let v = [1u32, 2u32];
        let g = refs(&v);
        let (a, b) = distinct_pair(&g, |&x| x == 1, |&x| x == 2).expect("pair");
        assert_eq!((*a, *b), (1, 2));
    }

    /// A dual-satisfying item PLUS a distinct partner still pairs (the
    /// guard suppresses only the lone self-chain, never real chains).
    #[test]
    fn dual_item_with_distinct_partner_pairs() {
        // v[0] satisfies both; v[1] satisfies only B.
        let v = [9u32, 2u32];
        let g = refs(&v);
        let got = distinct_pair(&g, |&x| x == 9, |&x| x == 2 || x == 9);
        // a must be the only A (v[0]); b must be the *distinct* v[1].
        let (a, b) = got.expect("distinct partner must pair");
        assert_eq!(*a, 9);
        assert_eq!(*b, 2);
    }

    #[test]
    fn empty_group_is_none() {
        let g: Vec<&u32> = Vec::new();
        assert_eq!(distinct_pair(&g, |_| true, |_| true), None);
    }

    /// Two value-equal but distinct objects ARE a pair  -  identity is
    /// by pointer, not by value (two findings with the same fields are
    /// still two independent findings).
    #[test]
    fn value_equal_but_distinct_objects_pair() {
        let v = [5u32, 5u32];
        let g = refs(&v);
        assert!(has_distinct_pair(&g, |&x| x == 5, |&x| x == 5));
    }

    fn brute_force_exists(a_mask: &[bool], b_mask: &[bool]) -> bool {
        for i in 0..a_mask.len() {
            for j in 0..b_mask.len() {
                if i != j && a_mask[i] && b_mask[j] {
                    return true;
                }
            }
        }
        false
    }

    proptest! {
        /// `distinct_pair` agrees with an O(n²) brute-force oracle for
        /// arbitrary predicate membership over up to 40 items, 4096
        /// cases.
        #[test]
        fn matches_brute_force_oracle(
            masks in proptest::collection::vec((any::<bool>(), any::<bool>()), 0..40)
        ) {
            // Distinct objects: index array, predicates read the mask
            // by *position* via pointer offset into the slice.
            let items: Vec<usize> = (0..masks.len()).collect();
            let g = refs(&items);
            let a_mask: Vec<bool> = masks.iter().map(|m| m.0).collect();
            let b_mask: Vec<bool> = masks.iter().map(|m| m.1).collect();

            let got = has_distinct_pair(
                &g,
                |&i| a_mask[i],
                |&i| b_mask[i],
            );
            prop_assert_eq!(got, brute_force_exists(&a_mask, &b_mask));
        }

        /// Existence of a result is invariant under permutation.
        #[test]
        fn existence_is_permutation_invariant(
            mut masks in proptest::collection::vec((any::<bool>(), any::<bool>()), 1..30),
            seed in any::<u64>(),
        ) {
            let items: Vec<usize> = (0..masks.len()).collect();
            let g = refs(&items);
            let a: Vec<bool> = masks.iter().map(|m| m.0).collect();
            let b: Vec<bool> = masks.iter().map(|m| m.1).collect();
            let before = has_distinct_pair(&g, |&i| a[i], |&i| b[i]);

            // Deterministic shuffle of the mask order.
            let n = masks.len();
            let mut s = seed | 1;
            for i in (1..n).rev() {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                let j = (s >> 33) as usize % (i + 1);
                masks.swap(i, j);
            }
            let items2: Vec<usize> = (0..masks.len()).collect();
            let g2 = refs(&items2);
            let a2: Vec<bool> = masks.iter().map(|m| m.0).collect();
            let b2: Vec<bool> = masks.iter().map(|m| m.1).collect();
            let after = has_distinct_pair(&g2, |&i| a2[i], |&i| b2[i]);

            prop_assert_eq!(before, after);
        }

        /// Any returned pair genuinely satisfies the predicates and is
        /// two distinct objects.
        #[test]
        fn returned_pair_is_sound(
            masks in proptest::collection::vec((any::<bool>(), any::<bool>()), 0..30)
        ) {
            let items: Vec<usize> = (0..masks.len()).collect();
            let g = refs(&items);
            let a: Vec<bool> = masks.iter().map(|m| m.0).collect();
            let b: Vec<bool> = masks.iter().map(|m| m.1).collect();
            if let Some((x, y)) = distinct_pair(&g, |&i| a[i], |&i| b[i]) {
                prop_assert!(a[*x], "returned A does not satisfy pred_a");
                prop_assert!(b[*y], "returned B does not satisfy pred_b");
                prop_assert!(!std::ptr::eq(x, y), "returned the same object twice");
            }
        }
    }
}
