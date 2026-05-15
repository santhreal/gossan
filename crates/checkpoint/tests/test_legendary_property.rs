use gossan_checkpoint::CheckpointStore;
use gossan_core::{DiscoverySource, DomainTarget, Target};
use proptest::prelude::*;
use secfinding::{Finding, Severity};

fn in_memory() -> CheckpointStore {
    CheckpointStore::open(":memory:").expect("in-memory store")
}

prop_compose! {
    fn arb_target()(domain in "[a-z0-9.-]{1,63}") -> Target {
        Target::Domain(DomainTarget {
            domain,
            source: DiscoverySource::Seed,
        })
    }
}

prop_compose! {
    fn arb_finding()(
        scanner in "[a-z]{1,10}",
        seed in "[a-z0-9.-]{1,63}",
        title in "[A-Za-z0-9 ]{1,100}",
        detail in "[A-Za-z0-9 ]{1,100}"
    ) -> Finding {
        Finding::builder(&scanner, &seed, Severity::Info)
            .title(title)
            .detail(detail)
            .build()
            .unwrap()
    }
}

proptest! {
    #[test]
    fn prop_save_and_load_invariant(
        seed in "\\PC*",
        stage_name in "\\PC*",
        config in "\\PC*",
        targets in prop::collection::vec(arb_target(), 0..10),
        findings in prop::collection::vec(arb_finding(), 0..10),
    ) {
        let store = in_memory();

        // We only proceed if new_scan doesn't fail (SQLite might reject some weird things if it's not text or has null bytes, though rusqlite usually handles it)
        if let Ok(id) = store.new_scan(&seed, &config) {
            // Save
            let res = store.save_stage(id, &stage_name, &targets, &findings);
            prop_assert!(res.is_ok(), "Failed to save stage");

            // Load
            let record = store.load(id).expect("Failed to load");

            // Invariants
            prop_assert_eq!(&record.seed, &seed);

            let loaded_stage = record.stage(&stage_name).expect("Stage should exist");
            prop_assert_eq!(&loaded_stage.stage, &stage_name);

            // Note: Since `Target` and `Finding` types might not derive PartialEq directly,
            // or we might lose some minor typing info across JSON serialization,
            // we compare serialized forms or sizes for strict equality
            prop_assert_eq!(loaded_stage.targets.len(), targets.len());
            prop_assert_eq!(loaded_stage.findings.len(), findings.len());

            // Deep check JSON string representation for exact equality since it went through JSON in DB
            let t_json_in = serde_json::to_string(&targets).unwrap();
            let t_json_out = serde_json::to_string(&loaded_stage.targets).unwrap();
            prop_assert_eq!(t_json_in, t_json_out);

            let f_json_in = serde_json::to_string(&findings).unwrap();
            let f_json_out = serde_json::to_string(&loaded_stage.findings).unwrap();
            prop_assert_eq!(f_json_in, f_json_out);
        }
    }

    #[test]
    fn prop_delete_removes_from_list(
        seed1 in "[a-zA-Z0-9]+",
        seed2 in "[a-zA-Z0-9]+"
    ) {
        let store = in_memory();
        let id1 = store.new_scan(&seed1, "{}").unwrap();
        let id2 = store.new_scan(&seed2, "{}").unwrap();

        store.delete_scan(id1).unwrap();

        let scans = store.list_scans().unwrap();

        // Invariants
        // id1 should NOT be in the list
        prop_assert!(!scans.iter().any(|(id, _, _)| *id == id1));
        // id2 SHOULD be in the list
        prop_assert!(scans.iter().any(|(id, _, _)| *id == id2));
    }
}
