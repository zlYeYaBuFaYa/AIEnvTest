use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
pub struct CertFacts {
    pub issuer: String,
    pub subject: String,
    pub verified: bool,
    pub error: Option<String>,
}

pub async fn inspect(host: &str) -> CertFacts {
    match inspect_inner(host).await {
        Ok(facts) => facts,
        Err(error) => CertFacts {
            issuer: String::new(),
            subject: String::new(),
            verified: false,
            error: Some(error),
        },
    }
}

async fn inspect_inner(host: &str) -> Result<CertFacts, String> {
    let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let verified = Arc::new(Mutex::new(false));
    let verify_error = Arc::new(Mutex::new(None));
    let verifier = Arc::new(CapturingVerifier {
        inner: webpki_verifier()?,
        captured: captured.clone(),
        verified: verified.clone(),
        verify_error: verify_error.clone(),
    });
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    );
    let stream = timeout(Duration::from_secs(8), TcpStream::connect((host, 443)))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|err| err.to_string())?;
    let connector = TlsConnector::from(config);
    let name = ServerName::try_from(host.to_string()).map_err(|err| err.to_string())?;
    let _tls = timeout(Duration::from_secs(8), connector.connect(name, stream))
        .await
        .map_err(|_| "tls timeout".to_string())?
        .map_err(|err| err.to_string())?;
    let der = captured.lock().map_err(|err| err.to_string())?.clone().ok_or("no certificate")?;
    let (_, cert) = X509Certificate::from_der(&der).map_err(|err| err.to_string())?;
    let verified_flag = *verified.lock().map_err(|err| err.to_string())?;
    let error = verify_error.lock().map_err(|err| err.to_string())?.clone();
    Ok(CertFacts {
        issuer: cert.issuer().to_string(),
        subject: cert.subject().to_string(),
        verified: verified_flag,
        error,
    })
}

fn webpki_verifier() -> Result<Arc<WebPkiServerVerifier>, String> {
    let config = super::http::build_tls_config();
    // Rebuild a verifier from the same root store by parsing the client config is not public.
    // Construct a fresh store the same way build_tls_config does.
    let mut roots = rustls::RootCertStore::empty();
    let natives = rustls_native_certs::load_native_certs();
    for cert in natives.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let _ = config;
    WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|err| err.to_string())
}

#[derive(Debug)]
struct CapturingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    captured: Arc<Mutex<Option<Vec<u8>>>>,
    verified: Arc<Mutex<bool>>,
    verify_error: Arc<Mutex<Option<String>>>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if let Ok(mut slot) = self.captured.lock() {
            *slot = Some(end_entity.as_ref().to_vec());
        }
        match self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
            Ok(verified) => {
                if let Ok(mut flag) = self.verified.lock() {
                    *flag = true;
                }
                Ok(verified)
            }
            Err(err) => {
                if let Ok(mut slot) = self.verify_error.lock() {
                    *slot = Some(err.to_string());
                }
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
