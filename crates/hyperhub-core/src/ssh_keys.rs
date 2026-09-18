//! SSH 私钥/公钥工具：生成、导入、公钥预览与指纹。供 TUI 与 SSH 凭证插件使用。
//!
//! 统一使用 russh 重导出的 `ssh_key`（russh 依赖已开启 `rsa`/`ring` feature），
//! 避免 CLI 直接依赖底层密钥库。

use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use std::path::Path;
use zeroize::Zeroizing;

/// 公钥预览信息：算法名、OpenSSH 公钥行、SHA-256 指纹。
pub struct PublicKeyInfo {
    pub algorithm: String,
    pub openssh: String,
    pub fingerprint: String,
}

/// 生成一个 RSA 私钥并编码为 OpenSSH PEM（`-----BEGIN OPENSSH PRIVATE KEY-----`）。
pub fn generate_rsa_private_key() -> Result<Zeroizing<String>, String> {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Rsa { hash: None })
        .map_err(|error| format!("生成 RSA 私钥失败：{error}"))?;
    key.to_openssh(LineEnding::LF)
        .map_err(|error| format!("编码 OpenSSH 私钥失败：{error}"))
}

/// 读取并校验 OpenSSH PEM 私钥文件，原样返回其内容。
///
/// 返回前会解析一次，保证导入的私钥能被后续 SSH 认证与公钥预览使用。
pub fn import_private_key(path: &Path) -> Result<Zeroizing<String>, String> {
    let pem = std::fs::read_to_string(path)
        .map_err(|error| format!("无法读取私钥文件 {}：{error}", path.display()))?;
    parse_private_key(&pem)?;
    Ok(Zeroizing::new(pem))
}

/// 从 PEM 私钥内容解析出公钥信息（OpenSSH 公钥行 + SHA-256 指纹）。
pub fn public_key_info(pem: &str) -> Result<PublicKeyInfo, String> {
    let key = parse_private_key(pem)?;
    let public = key.public_key();
    let openssh = public
        .to_openssh()
        .map_err(|error| format!("编码公钥失败：{error}"))?;
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    Ok(PublicKeyInfo {
        algorithm: public.algorithm().to_string(),
        openssh,
        fingerprint,
    })
}

/// 生成私钥的默认展示名：`"{算法} SHA256:{指纹前 12 字符}…"`。
pub fn short_label(pem: &str) -> Result<String, String> {
    let info = public_key_info(pem)?;
    let digest = info
        .fingerprint
        .strip_prefix("SHA256:")
        .unwrap_or(&info.fingerprint);
    let short = digest.chars().take(12).collect::<String>();
    Ok(format!("{} SHA256:{short}…", info.algorithm))
}

fn parse_private_key(pem: &str) -> Result<PrivateKey, String> {
    PrivateKey::from_openssh(pem.as_bytes())
        .map_err(|error| format!("无效的 OpenSSH 私钥：{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_rsa_key_exposes_public_key_and_fingerprint() {
        let pem = generate_rsa_private_key().expect("generate rsa key");
        let info = public_key_info(pem.as_str()).expect("public key info");
        assert_eq!(info.algorithm, "ssh-rsa");
        assert!(info.openssh.starts_with("ssh-rsa "));
        assert!(info.fingerprint.starts_with("SHA256:"));
        let label = short_label(pem.as_str()).expect("short label");
        assert!(label.starts_with("ssh-rsa SHA256:"));
        assert!(label.ends_with('…'));
    }

    #[test]
    fn import_parses_valid_openssh_pem() {
        let pem = generate_rsa_private_key().expect("generate rsa key");
        let dir = std::env::temp_dir().join(format!("hyperhub-ssh-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id_rsa");
        std::fs::write(&path, pem.as_bytes()).unwrap();
        let imported = import_private_key(&path).expect("import private key");
        assert_eq!(imported.as_str().trim(), pem.as_str().trim());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn import_rejects_invalid_pem() {
        let dir = std::env::temp_dir().join(format!("hyperhub-ssh-key-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("invalid");
        std::fs::write(&path, b"not a key").unwrap();
        let error = import_private_key(&path).unwrap_err();
        assert!(error.contains("无效的 OpenSSH 私钥"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
