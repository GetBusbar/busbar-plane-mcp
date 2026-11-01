use super::*;

#[test]
fn a_declared_host_checks_both_authority_readings() {
    for format in ["hostname", "idn-hostname", "ipv4", "ipv6"] {
        let schema = json!({"properties":{"target":{"format":format}}});
        let args = json!({"target":"public.example\\@169.254.169.254"});
        let error = guard(&schema, &args, public()).expect_err("the RFC host must be judged too");
        assert_eq!(error.why, ArgWhy::CloudMetadata("169.254.169.254".into()));
        assert!(guard(&schema, &json!({"target":"api.example.com"}), public()).is_ok());
    }
}

#[test]
fn a_legacy_tuple_additional_items_schema_is_not_skipped() {
    let schema = json!({"items":[{"type":"string"}],"additionalItems":{"format":"hostname"}});
    let error = guard(&schema, &json!(["ordinary", "169.254.169.254"]), public())
        .expect_err("the tail schema declares a host");
    assert_eq!(error.pointer, "/1");
    assert_eq!(error.why, ArgWhy::CloudMetadata("169.254.169.254".into()));
    let ok = guard(&schema, &json!(["ordinary", "api.example.com"]), public()).unwrap();
    assert_eq!(ok.declared_judged, 1);
}
