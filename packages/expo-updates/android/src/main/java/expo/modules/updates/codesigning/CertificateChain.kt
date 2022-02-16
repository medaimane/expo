package expo.modules.updates.codesigning

import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

// ASN.1 path to the extended key usage info within a CERT
private const val CODE_SIGNING_OID = "1.3.6.1.5.5.7.3.3"

/**
 * Full certificate chain for verifying code signing.
 * The chain should look like the following:
 *    0: code signing certificate
 *    1...n-1: intermediate certificates
 *    n: root certificate
 *
 * Requirements:
 * - Length(certificateChain) > 0
 * - certificate chain is valid and each certificate is valid
 * - 0th certificate is a valid code signing certificate
 */
class CertificateChain(private val certificateStrings: List<String>) {
  val codeSigningCertificate: X509Certificate by lazy {
    if (certificateStrings.isEmpty()) {
      throw CertificateException("No code signing certificates provided")
    }

    val certificateChain = certificateStrings.map { constructCertificate(it) }
    certificateChain.validateChain()
    val leafCertificate = certificateChain[0]
    if (!leafCertificate.isCodeSigningCertificate()) {
      throw CertificateException("First certificate in chain is not a code signing certificate. Must have X509v3 Key Usage: Digital Signature and X509v3 Extended Key Usage: Code Signing")
    }
    leafCertificate
  }

  companion object {
    private fun constructCertificate(certificateString: String): X509Certificate {
      return (
        CertificateFactory.getInstance("X.509")
          .generateCertificate(certificateString.byteInputStream()) as X509Certificate
        ).apply {
        checkValidity()
      }
    }

    private fun X509Certificate.isCodeSigningCertificate(): Boolean {
      return keyUsage != null && keyUsage.isNotEmpty() && keyUsage[0] && extendedKeyUsage.contains(
        CODE_SIGNING_OID
      )
    }

    private fun List<X509Certificate>.validateChain() {
      for (i in 0 until size - 1) {
        val cert = get(i)
        val issuer = get(i + 1)
        if (!cert.issuerX500Principal.equals(issuer.subjectX500Principal)) {
          throw CertificateException("Certificates do not chain")
        }
        cert.verify(issuer.publicKey)
      }
      // last (root) must be self-signed, verify the final cert
      if (!last().issuerX500Principal.equals(last().subjectX500Principal)) {
        throw CertificateException("Root certificate not self-signed")
      }
      last().verify(last().publicKey)
    }
  }
}
