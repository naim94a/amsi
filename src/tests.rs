use super::*;

#[test]
fn eicar_test() {
    let eicar_test: &str = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    let ctx = AmsiContext::new("Test").unwrap();
    let s1 = ctx.create_session().unwrap();
    let s2 = ctx.create_session().unwrap();
    let r1 = s1.scan_buffer("eicar-test.txt", eicar_test.as_bytes()).unwrap();
    let r2 = s2.scan_string("eicar-test.txt", eicar_test).unwrap();
    assert!(r1.is_malware());
    assert!(r2.is_malware());
}

#[test]
fn clean_test() {
    let ctx = AmsiContext::new("mytest").unwrap();
    let s = ctx.create_session().unwrap();
    let res = s.scan_string("test.txt", "Nothing wrong with this.").unwrap();
    assert!(res.is_not_detected() || res.is_clean());
}