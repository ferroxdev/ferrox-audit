use std::sync::atomic::{AtomicU64, Ordering};

const HOST: &str = "carrier.test";
static TEMP: AtomicU64 = AtomicU64::new(0);

/// Mints the `TLS` arm's certificate and key into the directory the caller names, because a
/// private key in the tree is a leak surface `check-fixture-safety.sh` refuses.
pub fn run(args: &[String]) -> i32 {
    let ensure = args.iter().any(|arg| arg == "--ensure");
    let Some(dir) = args.iter().find(|arg| *arg != "--ensure") else {
        eprintln!("make-tls needs one argument: the directory for cert.pem and key.pem");
        return 2;
    };
    if let Err(e) = write_pair(std::path::Path::new(dir.as_str()), ensure) {
        eprintln!("make-tls: {e}");
        return 1;
    }
    0
}

fn write_pair(dir: &std::path::Path, ensure: bool) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let lock = lock_dir(dir)?;
    if ensure && ready(dir) {
        drop(lock);
        return Ok(());
    }
    let minted = mint()?;
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let mut temps = Vec::new();
    let result = (|| {
        let cert_tmp = write_temp(dir, ".cert.pem", minted.cert.pem().as_bytes(), false)?;
        temps.push(cert_tmp.clone());
        let key_tmp = write_temp(
            dir,
            ".key.pem",
            minted.signing_key.serialize_pem().as_bytes(),
            true,
        )?;
        temps.push(key_tmp.clone());
        publish(&cert, &key, &cert_tmp, &key_tmp)
    })();
    for path in temps {
        let _ = std::fs::remove_file(path);
    }
    drop(lock);
    result
}

fn ready(dir: &std::path::Path) -> bool {
    [dir.join("cert.pem"), dir.join("key.pem")]
        .iter()
        .all(|path| path.metadata().is_ok_and(|meta| meta.len() > 0))
}

fn lock_dir(dir: &std::path::Path) -> Result<std::fs::File, String> {
    let path = dir.join(".make-tls.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.lock()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(file)
}

fn publish(
    cert: &std::path::Path,
    key: &std::path::Path,
    cert_tmp: &std::path::Path,
    key_tmp: &std::path::Path,
) -> Result<(), String> {
    // `cert.pem` is the readiness marker; remove it before the key, so a new key never pairs with the old certificate.
    for path in [cert, key] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    std::fs::rename(key_tmp, key).map_err(|e| format!("{}: {e}", key.display()))?;
    std::fs::rename(cert_tmp, cert).map_err(|e| format!("{}: {e}", cert.display()))?;
    Ok(())
}

fn write_temp(
    dir: &std::path::Path,
    stem: &str,
    bytes: &[u8],
    private: bool,
) -> Result<std::path::PathBuf, String> {
    use std::io::Write as _;
    for _ in 0..16 {
        let name = format!(
            "{stem}.{}.{}.tmp",
            std::process::id(),
            TEMP.fetch_add(1, Ordering::Relaxed)
        );
        let path = dir.join(name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(if private { 0o600 } else { 0o644 });
        }
        #[cfg(not(unix))]
        let _ = private;
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let result = file.write_all(bytes);
        #[cfg(unix)]
        let result = result.and_then(|()| {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = if private { 0o600 } else { 0o644 };
            file.set_permissions(std::fs::Permissions::from_mode(mode))
        });
        drop(file);
        if let Err(error) = result {
            let _ = std::fs::remove_file(&path);
            return Err(format!("{}: {error}", path.display()));
        }
        return Ok(path);
    }
    Err(format!(
        "{}: could not create a temporary file",
        dir.display()
    ))
}

/// `carrier.test` as both the subject and the one DNS alternative name, because a verifier reads
/// the alternative name and never the subject, so a CN-only certificate is refused by all of them.
fn mint() -> Result<rcgen::CertifiedKey<rcgen::KeyPair>, String> {
    let mut params =
        rcgen::CertificateParams::new(vec![HOST.to_owned()]).map_err(|e| e.to_string())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOST);
    let key_pair = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    Ok(rcgen::CertifiedKey {
        cert,
        signing_key: key_pair,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arm's checker: the pair lands as PEM the references read, and the certificate that
    /// came with it names `carrier.test` as a DNS alternative name.
    #[test]
    fn the_minted_pair_names_the_carrier() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ferrox-matrix-tls-{}-{stamp}", std::process::id()));
        write_pair(&dir, false).expect("the pair is minted");
        let cert = std::fs::read_to_string(dir.join("cert.pem")).expect("a certificate");
        let key = std::fs::read_to_string(dir.join("key.pem")).expect("a key");
        write_pair(&dir, true).expect("the existing pair is reused");
        assert_eq!(
            std::fs::read_to_string(dir.join("cert.pem")).expect("a certificate"),
            cert
        );
        std::fs::remove_dir_all(&dir).expect("the fixture is cleaned up");
        assert!(cert.contains("BEGIN CERTIFICATE"), "{cert}");
        assert!(key.contains("PRIVATE KEY"), "{key}");
        let minted = mint().expect("mints");
        let cert = webpki::EndEntityCert::try_from(minted.cert.der()).expect("parses");
        let name = rustls_pki_types::DnsName::try_from(HOST).expect("a dns name");
        cert.verify_is_valid_for_subject_name(&rustls_pki_types::ServerName::DnsName(name))
            .expect("the certificate names the carrier");
    }
}
