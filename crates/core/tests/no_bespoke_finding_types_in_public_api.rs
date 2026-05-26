//! Phase 06: gossan-core public finding types are secfinding re-exports.

use std::any::TypeId;

#[test]
fn public_finding_type_is_secfinding() {
    assert_eq!(
        TypeId::of::<gossan_core::Finding>(),
        TypeId::of::<secfinding::Finding>(),
        "gossan_core::Finding must be secfinding::Finding"
    );
}
