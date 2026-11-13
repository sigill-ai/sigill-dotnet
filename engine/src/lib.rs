//! A C ABI over `cedar_policy::ffi`, built as a wasm32-wasip1 module.
//! Host: p = cedar_alloc(n); write JSON; out = cedar_authorize(p, n, &len); read len bytes at out;
//! cedar_free(out, len); cedar_free(p, n). Input/output JSON is exactly cedar_policy::ffi's
//! (= cedar-wasm's isAuthorized / validate call and answer objects).
use cedar_policy::ffi;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[no_mangle]
pub extern "C" fn cedar_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// # Safety
/// `ptr`/`len` must come from `cedar_alloc` or from an output of this library.
#[no_mangle]
pub unsafe extern "C" fn cedar_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

unsafe fn give(s: String, out_len: *mut usize) -> *mut u8 {
    let b = s.into_bytes().into_boxed_slice();
    *out_len = b.len();
    Box::into_raw(b) as *mut u8
}

unsafe fn call(ptr: *const u8, len: usize, out_len: *mut usize, f: fn(&str) -> Result<String, serde_json::Error>) -> *mut u8 {
    let input = std::slice::from_raw_parts(ptr, len);
    let out = catch_unwind(AssertUnwindSafe(|| match std::str::from_utf8(input) {
        Ok(s) => f(s).unwrap_or_else(|e| failure(&format!("invalid call JSON: {e}"))),
        Err(e) => failure(&format!("input is not UTF-8: {e}")),
    }))
    .unwrap_or_else(|_| failure("internal error: engine panicked"));
    give(out, out_len)
}

// Same shape as ffi's own failure answers: {"type":"failure","errors":[{"message":..}]}.
fn failure(msg: &str) -> String {
    serde_json::json!({"type": "failure", "errors": [{"message": msg, "help": null, "code": null, "url": null, "severity": null, "sourceLocations": [], "related": []}]}).to_string()
}

// reason and errors are hash sets in the core; sort them so an answer's bytes do not depend on the hash seed.
// Each policy reports at most one error, so policyId is a total order for errors.
fn authorize(s: &str) -> Result<String, serde_json::Error> {
    let mut v: serde_json::Value = serde_json::from_str(&ffi::is_authorized_json_str(s)?)?;
    if let Some(d) = v.pointer_mut("/response/diagnostics") {
        if let Some(r) = d.get_mut("reason").and_then(|x| x.as_array_mut()) {
            r.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        }
        if let Some(e) = d.get_mut("errors").and_then(|x| x.as_array_mut()) {
            e.sort_by(|a, b| a["policyId"].as_str().cmp(&b["policyId"].as_str()));
        }
    }
    serde_json::to_string(&v)
}

/// # Safety
/// `ptr` must point to `len` readable bytes; `out_len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn cedar_authorize(ptr: *const u8, len: usize, out_len: *mut usize) -> *mut u8 {
    call(ptr, len, out_len, authorize)
}

/// # Safety
/// As `cedar_authorize`.
#[no_mangle]
pub unsafe extern "C" fn cedar_validate(ptr: *const u8, len: usize, out_len: *mut usize) -> *mut u8 {
    call(ptr, len, out_len, ffi::validate_json_str)
}

/// The embedded core's SDK version (= cedar-wasm getCedarVersion()). Free the result like the others.
/// # Safety
/// `out_len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn cedar_version(out_len: *mut usize) -> *mut u8 {
    give(ffi::get_sdk_version(), out_len)
}
