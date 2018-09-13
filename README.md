# Antimalware Scan Interface for Rust
Starting from Windows 10, and Windows Server 2016 the "Antimalware Scan Interface" is available as a native API which allows programs that run on Windows to invoke an Antivirus to scan a payload for malware.

The API may be useful for servers to inspect payloads before passing them on, such as email servers and many more.

This crate is a safe wrapper around the native WinAPI.
The following functions are used:
* AmsiInitialize
* AmsiUninitialize
* AmsiOpenSession
* AmsiCloseSession
* AmsiScanString
* AmsiScanBuffer

## Getting Started
Add `amsi` as a dependency to your project.
```toml
[dependencies]
amsi = "0.1.0"
```
Start scanning payloads.
```rust
fn main() {
    let malicious_file = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let ctx = amsi::AmsiContext::new("emailscanner-1.0.0").unwrap();
    let session = ctx.create_session().unwrap();
    let result = session.scan_string(r"C:\eicar-test.txt", malicious_file).unwrap();
    if result.is_malware() {
        println!("This file is malicious!");
    } else {
        println!("Seems to be ok.");
    }
}
```
