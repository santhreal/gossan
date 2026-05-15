// `gossan-js` (the JS analysis crate) is excluded from the default
// workspace because it carries a cross-workspace dependency on
// keyhog. The tests below directly import `gossan_js::secrets` and
// therefore only build when the `js` feature is enabled (which itself
// pulls `gossan-js` in via the cli's optional dep). Without the gate
// `cargo test --workspace` failed at compile time on stock checkouts.
#[cfg(feature = "js")]
mod secret_detection;
#[cfg(feature = "js")]
mod noise_reduction;
