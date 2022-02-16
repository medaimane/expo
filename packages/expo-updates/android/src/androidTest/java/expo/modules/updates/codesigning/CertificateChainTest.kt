package expo.modules.updates.codesigning

import androidx.test.internal.runner.junit4.AndroidJUnit4ClassRunner
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SignatureException
import java.security.cert.CertificateException

@RunWith(AndroidJUnit4ClassRunner::class)
class CertificateChainTest {
  @Test
  fun test_ValidSingleCertificate() {
    Assert.assertNotNull(CertificateChain(listOf(CertificateFixtures.testCertificate)).codeSigningCertificate)
  }

  @Test(expected = CertificateException::class)
  @Throws(CertificateException::class)
  fun test_MultipleCertsInEmbeddedPEMThrowsError() {
    CertificateChain(listOf(CertificateFixtures.testCertificate + CertificateFixtures.testCertificate)).codeSigningCertificate
  }

  @Test
  fun test_ValidCertificateChain() {
    Assert.assertNotNull(CertificateChain(listOf(CertificateFixtures.testValidChainLeafCertificate, CertificateFixtures.testValidChainIntermediateCertificate, CertificateFixtures.testValidChainRootCertificate)).codeSigningCertificate)
  }

  @Test(expected = CertificateException::class)
  @Throws(CertificateException::class)
  fun test_RequiresLengthGreaterThanZero() {
    CertificateChain(listOf()).codeSigningCertificate
  }

  @Test(expected = CertificateException::class)
  @Throws(CertificateException::class)
  fun test_ThrowsWhenAnyCertificateIsInvalidDate() {
    CertificateChain(listOf(CertificateFixtures.testCertificateValidityExpired)).codeSigningCertificate
  }

  @Test(expected = CertificateException::class)
  @Throws(CertificateException::class)
  fun test_ThrowsWhenLeafIsNotCodeSigningNoKeyUsage() {
    CertificateChain(listOf(CertificateFixtures.testCertificateNoKeyUsage)).codeSigningCertificate
  }

  @Test(expected = CertificateException::class)
  @Throws(CertificateException::class)
  fun test_ThrowsWhenLeafIsNotCodeSigningNoCodeSigningExtendedKeyUsage() {
    CertificateChain(listOf(CertificateFixtures.testCertificateNoCodeSigningExtendedKeyUsage)).codeSigningCertificate
  }

  @Test(expected = CertificateException::class)
  @Throws(CertificateException::class)
  fun test_ThrowsChainIsNotValid() {
    // missing intermediate
    CertificateChain(listOf(CertificateFixtures.testValidChainLeafCertificate, CertificateFixtures.testValidChainRootCertificate)).codeSigningCertificate
  }

  @Test(expected = CertificateException::class)
  @Throws(CertificateException::class)
  fun test_ThrowsWhenRootIsNotSelfSigned() {
    // missing root, meaning intermediate is considered root and is not self-signed
    CertificateChain(listOf(CertificateFixtures.testValidChainLeafCertificate, CertificateFixtures.testValidChainIntermediateCertificate)).codeSigningCertificate
  }

  @Test(expected = SignatureException::class)
  @Throws(SignatureException::class)
  fun test_ThrowsWhenAnySignatureInvalid() {
    CertificateChain(listOf(CertificateFixtures.testInvalidSignatureChainLeafCertificate, CertificateFixtures.testValidChainIntermediateCertificate, CertificateFixtures.testValidChainRootCertificate)).codeSigningCertificate
  }

  @Test(expected = SignatureException::class)
  @Throws(SignatureException::class)
  fun test_ThrowsWhenRootSignatureInvalid() {
    CertificateChain(listOf(CertificateFixtures.testCertificateSignatureInvalid)).codeSigningCertificate
  }
}
