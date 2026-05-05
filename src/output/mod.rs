pub mod json;
pub mod text;

/// Compute the externalization percentage as a 0–100 integer, rounded.
///
/// Shared by the text and JSON formatters so the rounding rule stays in
/// lockstep across surfaces. Returns 0 when there are no enforcement
/// points at all (the "no signal" case the formatters short-circuit
/// before calling this anyway, but defined here too so the helper is
/// total).
pub(crate) fn externalized_pct(externalized: usize, embedded: usize) -> usize {
    let total = externalized + embedded;
    if total == 0 {
        return 0;
    }
    (externalized as f64 / total as f64 * 100.0).round() as usize
}

#[cfg(test)]
mod tests {
    use super::externalized_pct;

    #[test]
    fn zero_total_is_zero() {
        assert_eq!(externalized_pct(0, 0), 0);
    }

    #[test]
    fn all_externalized_is_one_hundred() {
        assert_eq!(externalized_pct(7, 0), 100);
    }

    #[test]
    fn none_externalized_is_zero() {
        assert_eq!(externalized_pct(0, 7), 0);
    }

    #[test]
    fn rounds_half_up() {
        // 1 / 3 = 33.333… → 33
        assert_eq!(externalized_pct(1, 2), 33);
        // 2 / 3 = 66.666… → 67
        assert_eq!(externalized_pct(2, 1), 67);
        // 1 / 2 = 50
        assert_eq!(externalized_pct(1, 1), 50);
    }
}
