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

#[derive(Debug)]
pub struct WinError {
    code: DWORD,
}

impl WinError {
    pub fn new() -> WinError {
        Self::from_code(unsafe {
            GetLastError()
        })
    }

    pub fn from_code(code: DWORD) -> WinError {
        WinError{
            code,
        }
    }

    pub fn from_hresult(res: HRESULT) -> WinError {
        Self::from_code(res & 0xffff)
    }
}

#[derive(Debug)]
pub struct AmsiContext {
    ctx: HAMSICONTEXT,
}

#[derive(Debug)]
pub struct AmsiSession<'a> {
    ctx: &'a AmsiContext,
    session: HAMSISESSION,
}

#[derive(Debug)]
pub struct AmsiResult {
    code: u32,
}

impl AmsiResult {
    pub fn new(code: u32) -> AmsiResult {
        AmsiResult{
            code,
        }
    }

    pub fn is_malware(&self) -> bool {
        self.code >= 32768
    }

    pub fn is_clean(&self) -> bool {
        self.code == 0
    }

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

#[cfg(test)]
mod tests {
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
}
