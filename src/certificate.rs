use std::{fs, path::PathBuf, process::Command};

use anyhow::{Context, Result, bail};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    },
    rustls::crypto::aws_lc_rs,
};

pub struct CertificateFiles {
    pub authority: RcgenAuthority,
    pub certificate_der: PathBuf,
    pub certificate_pem: PathBuf,
}

pub fn load_or_create_ca(directory: PathBuf) -> Result<CertificateFiles> {
    fs::create_dir_all(&directory).with_context(|| {
        format!(
            "cannot create the certificate directory {}",
            directory.display()
        )
    })?;
    let key_path = directory.join("http-whisper-ca.key");
    let pem_path = directory.join("http-whisper-ca.pem");
    let der_path = directory.join("http-whisper-ca.cer");

    if !key_path.exists() || !pem_path.exists() || !der_path.exists() {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "HTTP Whisper Local CA");
        name.push(DnType::OrganizationName, "HTTP Whisper");
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&key)?;
        fs::write(&key_path, key.serialize_pem())
            .with_context(|| format!("cannot save the CA private key at {}", key_path.display()))?;
        fs::write(&pem_path, cert.pem())
            .with_context(|| format!("cannot save the CA certificate at {}", pem_path.display()))?;
        fs::write(&der_path, cert.der().as_ref()).with_context(|| {
            format!(
                "cannot save the Windows CA certificate at {}",
                der_path.display()
            )
        })?;
    }

    let key = KeyPair::from_pem(&fs::read_to_string(&key_path)?)?;
    let issuer = Issuer::from_ca_cert_pem(&fs::read_to_string(&pem_path)?, key)?;
    Ok(CertificateFiles {
        authority: RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider()),
        certificate_der: der_path,
        certificate_pem: pem_path,
    })
}

pub fn install_current_user_ca(certificate: &std::path::Path) -> Result<()> {
    #[cfg(windows)]
    {
        let output = Command::new("certutil.exe")
            .args(["-user", "-addstore", "Root"])
            .arg(certificate)
            .output()
            .context("could not start certutil.exe")?;
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = format!("{} {}", stdout.trim(), stderr.trim());
            bail!(
                "Windows rejected the HTTP Whisper CA in the current-user Root store: {}",
                detail.trim()
            );
        }
    }
    #[cfg(not(windows))]
    let _ = certificate;
    Ok(())
}
