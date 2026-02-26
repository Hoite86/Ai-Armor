use anyhow::{anyhow, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};

#[cfg(target_os = "windows")]
use windows::core::PWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTOAPI_BLOB,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::LocalFree;

pub fn generate_passphrase() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    base64::encode(b)
}

pub fn hash_sha256(input: &str) -> String {
    let h = Sha256::digest(input.as_bytes());
    hex::encode(h)
}

#[cfg(target_os = "windows")]
pub fn protect_with_dpapi(plain: &[u8]) -> Result<Vec<u8>> {
    let mut in_blob = CRYPTOAPI_BLOB {
        cbData: plain.len() as u32,
        pbData: plain.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPTOAPI_BLOB::default();
    unsafe {
        CryptProtectData(
            &mut in_blob,
            PWSTR::null(),
            None,
            None,
            None,
            0,
            &mut out_blob,
        )
        .ok()
        .map_err(|e| anyhow!("CryptProtectData failed: {e}"))?;
        let out = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        let _ = LocalFree(out_blob.pbData as isize);
        Ok(out)
    }
}

#[cfg(target_os = "windows")]
pub fn unprotect_with_dpapi(cipher: &[u8]) -> Result<Vec<u8>> {
    let mut in_blob = CRYPTOAPI_BLOB {
        cbData: cipher.len() as u32,
        pbData: cipher.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPTOAPI_BLOB::default();
    unsafe {
        CryptUnprotectData(&mut in_blob, None, None, None, None, 0, &mut out_blob)
            .ok()
            .map_err(|e| anyhow!("CryptUnprotectData failed: {e}"))?;
        let out = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        let _ = LocalFree(out_blob.pbData as isize);
        Ok(out)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn protect_with_dpapi(plain: &[u8]) -> Result<Vec<u8>> {
    Ok(plain.to_vec())
}
#[cfg(not(target_os = "windows"))]
pub fn unprotect_with_dpapi(cipher: &[u8]) -> Result<Vec<u8>> {
    Ok(cipher.to_vec())
}
