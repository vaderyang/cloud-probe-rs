//! Narrowing helpers that keep the AUDIT4 P5-15 hygiene gate honest.
//!
//! `parity/verify_hygiene.sh` forbids a bare `as <integer>` cast anywhere in
//! the configuration layer, because such a cast silently *wraps*. The
//! `i64 -> i32` case is handled by `TryFrom` (see `config::int_in`), but Rust
//! has no `TryFrom<f64> for i64`: the only conversion is `as`, which for
//! float -> integer *saturates* (since Rust 1.45) instead of wrapping. It lives
//! here, behind a checked API, so the deserialising layer itself stays free of
//! `as` while still accepting the integral floats that cJSON accepts.

/// Convert an integral, finite `f64` to `i64`, saturating at the `i64` bounds.
///
/// Returns `None` for a non-finite or fractional value. Callers that clamp or
/// range-check the result make the saturation unobservable, exactly as C does
/// when it stores the `double` and compares it.
#[must_use]
pub(crate) fn integral_i64(f: f64) -> Option<i64> {
    if f.is_finite() && f.fract() == 0.0 {
        Some(f as i64)
    } else {
        None
    }
}
