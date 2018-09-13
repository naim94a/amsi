//! # Antimalware Scan Interface
//! The "Antimalware Scan Interface" is an API by Microsoft, this crate is a safe wrapper for the native API.
//!
//! ## Example
//! ```
//! extern crate amsi;
//!
//! fn main() {
//!     let malicious_file = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
//!     let ctx = amsi::AmsiContext::new("emailscanner-1.0.0").unwrap();
//!     let session = ctx.create_session().unwrap();
//!     let result = session.scan_string(r"C:\eicar-test.txt", malicious_file).unwrap();
//!     println!("malicious = {}", result.is_malware());
//! }
//! ```
//!
//! ## Note
//! This crate only works with Windows 10, or Windows Server 2016 and above due to the API it wraps.

#[cfg(test)]
mod tests;

type HRESULT = u32;
type LPCWSTR = *const u16;
type HAMSICONTEXT = *const u8;
type HAMSISESSION = *const u8;
type DWORD = u32;
type AMSI_RESULT = u32;

#[link(name="amsi")]
extern "system" {
    fn AmsiInitialize(name: LPCWSTR, context: &mut HAMSICONTEXT) -> HRESULT;
    fn AmsiUninitialize(content: HAMSICONTEXT);
    fn AmsiScanString(context: HAMSICONTEXT, string: LPCWSTR, content_name: LPCWSTR, session: HAMSISESSION, result: &mut AMSI_RESULT) -> HRESULT;
    fn AmsiScanBuffer(context: HAMSICONTEXT, buffer: *const u8, length: usize, content_name: LPCWSTR, session: HAMSISESSION, result: &mut AMSI_RESULT) -> HRESULT;
    fn AmsiOpenSession(context: HAMSICONTEXT, session: &mut HAMSISESSION) -> HRESULT;
    fn AmsiCloseSession(context: HAMSICONTEXT, session: HAMSISESSION);
}

#[link(name="kernel32")]
extern "system" {
    fn GetLastError() -> DWORD;
}

/// Represents a Windows Error
#[derive(Debug)]
pub struct WinError {
    code: DWORD,
}

impl WinError {
    /// Creates a new `WinError`. This function will actually call `GetLastError()`.
    pub fn new() -> WinError {
        Self::from_code(unsafe {
            GetLastError()
        })
    }

    /// Creates a new `WinError` from the specified error code.
    pub fn from_code(code: DWORD) -> WinError {
        WinError{
            code,
        }
    }

    /// Creates a new `WinError` from the specified `HRESULT` code.
    pub fn from_hresult(res: HRESULT) -> WinError {
        Self::from_code(res & 0xffff)
    }
}

/// A Context that can be used for scanning payloads.
#[derive(Debug)]
pub struct AmsiContext {
    ctx: HAMSICONTEXT,
}

/// Represents a scan session.
#[derive(Debug)]
pub struct AmsiSession<'a> {
    ctx: &'a AmsiContext,
    session: HAMSISESSION,
}

/// Allows you to tell if a scan result is malicious or not.
///
/// This structure is returned by scan functions.
#[derive(Debug)]
pub struct AmsiResult {
    code: u32,
}

impl AmsiResult {
    pub(crate) fn new(code: u32) -> AmsiResult {
        AmsiResult{
            code,
        }
    }

    /// Returns `true` if the result is malicious.
    pub fn is_malware(&self) -> bool {
        self.code >= 32768
    }

    /// Returns `true` if the result is not malicious and will probably never be.
    pub fn is_clean(&self) -> bool {
        self.code == 0
    }

    /// Returns `true` if the result is not malicious, but might be malicious with future definition updates.
    pub fn is_not_detected(&self) -> bool {
        self.code == 1
    }

    pub fn is_blocked_by_admin(&self) -> bool {
        self.code >= 0x4000 && self.code <= 0x4fff
    }

    pub fn get_code(&self) -> u32 {
        self.code
    }
}

impl AmsiContext {
    /// Creates a new AMSI context.
    ///
    /// ## Parameters
    /// * **app_name** - name, version or GUID of the application using AMSI API.
    pub fn new(app_name: &str) -> Result<AmsiContext, WinError> {
        let name_utf16: Vec<u16> = app_name.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut amsi_ctx = std::mem::zeroed::<HAMSICONTEXT>();

            let res = AmsiInitialize(name_utf16.as_ptr(), &mut amsi_ctx);

            if res == 0 {
                Ok(AmsiContext{
                    ctx: amsi_ctx,
                })
            }
            else {
                Err(WinError::from_hresult(res))
            }
        }
    }

    /// Creates a scan session from the current context.
    pub fn create_session<'a>(&self) -> Result<AmsiSession, WinError> {
        unsafe {
            let mut session = std::mem::zeroed::<HAMSISESSION>();
            let res = AmsiOpenSession(self.ctx, &mut session);
            if res == 0 {
                Ok(AmsiSession{
                    ctx: self,
                    session,
                })
            } else {
                Err(WinError::from_hresult(res))
            }
        }
    }
}

impl<'a> AmsiSession<'a> {
    /// Scans a string
    ///
    /// This is usually useful for scanning scripts.
    ///
    /// ## Parameters
    /// * **content_name** - File name, URL or unique script ID
    /// * **data** - Content that should be scanned.
    pub fn scan_string(&self, content_name: &str, data: &str) -> Result<AmsiResult, WinError> {
        let name : Vec<u16> = content_name.encode_utf16().chain(std::iter::once(0)).collect();
        let content: Vec<u16> = data.encode_utf16().chain(std::iter::once(0)).collect();

        let mut result = 0;

        let res = unsafe {
            AmsiScanString(self.ctx.ctx, content.as_ptr(), name.as_ptr(), self.session, &mut result)
        };

        if res == 0 {
            Ok(AmsiResult::new(result))
        }
        else {
            Err(WinError::from_hresult(res))
        }
    }

    /// Scans a buffer
    ///
    /// ## Parameters
    /// * **content_name** - File name, URL or unique script ID.
    /// * **data** - payload that should be scanned.
    pub fn scan_buffer(&self, content_name: &str, data: &[u8]) -> Result<AmsiResult, WinError> {
        let name: Vec<u16> = content_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut result = 0;

        let hres = unsafe {
            AmsiScanBuffer(self.ctx.ctx, data.as_ptr(), data.len(), name.as_ptr(), self.session, &mut result)
        };

        if hres == 0 {
            Ok(AmsiResult::new(result))
        } else {
            Err(WinError::from_hresult(hres))
        }
    }
}

impl Drop for AmsiContext {
    fn drop(&mut self) {
        unsafe {
            AmsiUninitialize(self.ctx);
        }
    }
}

impl<'a> Drop for AmsiSession<'a> {
    fn drop(&mut self) {
        unsafe {
            AmsiCloseSession(self.ctx.ctx, self.session);
        }
    }
}