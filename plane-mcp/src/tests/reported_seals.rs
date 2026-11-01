use super::*;

#[test]
fn a_malformed_host_signature_never_mints_an_unopenable_seal() {
    for len in [0, 1, SIGNATURE_LEN - 1, SIGNATURE_LEN + 1] {
        assert_eq!(seal_state(&state(), &mut |_| Some(vec![7; len])), None);
        assert_eq!(seal_bytes(b"resume", &mut |_| Some(vec![7; len])), None);
    }
    let sealed = seal_bytes(b"resume", &mut sign).expect("a full signature");
    assert!(opens(b"resume", &sealed, &mut sign));
}
