package expo.modules.updates.codesigning

import androidx.test.internal.runner.junit4.AndroidJUnit4ClassRunner
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4ClassRunner::class)
class CodeSigningConfigurationTest {
  @Test
  fun test_separateCertificateChain() {
    val chain1 = CodeSigningConfiguration.separateCertificateChain(
      CertificateFixtures.testValidChainLeafCertificate
    )
    Assert.assertEquals(1, chain1.size)

    val chain2 = CodeSigningConfiguration.separateCertificateChain(
      CertificateFixtures.testValidChainLeafCertificate + CertificateFixtures.testValidChainIntermediateCertificate
    )
    Assert.assertEquals(2, chain2.size)

    val chain3 = CodeSigningConfiguration.separateCertificateChain(
      CertificateFixtures.testValidChainLeafCertificate + CertificateFixtures.testValidChainIntermediateCertificate + CertificateFixtures.testValidChainRootCertificate
    )
    Assert.assertEquals(3, chain3.size)

    val chainWithABunchOfNewlinesAndStuff = CodeSigningConfiguration.separateCertificateChain(
      CertificateFixtures.testCertificate + "\n\n\n\n" + CertificateFixtures.testCertificate
    )
    Assert.assertEquals(2, chainWithABunchOfNewlinesAndStuff.size)
  }

  @Test
  fun test_getAcceptSignatureHeader_CreatesSignatureHeaderDefaultValues() {
    val configuration = CodeSigningConfiguration(CertificateFixtures.testCertificate, mapOf(), false)
    val signatureHeader = configuration.getAcceptSignatureHeader()
    Assert.assertEquals(signatureHeader, "sig, keyid=\"root\", alg=\"rsa-v1_5-sha256\"")
  }

  @Test
  fun test_getAcceptSignatureHeader_CreatesSignatureHeaderValuesFromConfig() {
    val configuration = CodeSigningConfiguration(
      CertificateFixtures.testCertificate,
      mapOf(
        CODE_SIGNING_METADATA_ALGORITHM_KEY to "rsa-v1_5-sha256",
        CODE_SIGNING_METADATA_KEY_ID_KEY to "test"
      ),
      false
    )
    val signatureHeader = configuration.getAcceptSignatureHeader()
    Assert.assertEquals(signatureHeader, "sig, keyid=\"test\", alg=\"rsa-v1_5-sha256\"")
  }

  @Test
  fun test_getAcceptSignatureHeader_CreatesSignatureHeaderEscapedValues() {
    val configuration = CodeSigningConfiguration(
      CertificateFixtures.testCertificate,
      mapOf(
        CODE_SIGNING_METADATA_ALGORITHM_KEY to "rsa-v1_5-sha256",
        CODE_SIGNING_METADATA_KEY_ID_KEY to """test"hello\"""
      ),
      false
    )
    val signatureHeader = configuration.getAcceptSignatureHeader()
    Assert.assertEquals("""sig, keyid="test\"hello\\", alg="rsa-v1_5-sha256"""", signatureHeader)
  }

  @Test
  fun test_validateSignature_Valid() {
    val codeSigningConfiguration = CodeSigningConfiguration(CertificateFixtures.testCertificate, mapOf(), false)
    val codesigningInfo = SignatureHeaderInfo.parseSignatureHeader(CertificateFixtures.testSignature)
    val isValid = codeSigningConfiguration.validateSignature(codesigningInfo, CertificateFixtures.testBody.toByteArray(), null)
    Assert.assertTrue(isValid)
  }

  @Test
  fun test_validateSignature_ReturnsFalseWhenSignatureIsInvalid() {
    val codeSigningConfiguration = CodeSigningConfiguration(CertificateFixtures.testCertificate, mapOf(), false)
    val codesigningInfo = SignatureHeaderInfo.parseSignatureHeader("sig=\"aGVsbG8=\"")
    val isValid = codeSigningConfiguration.validateSignature(codesigningInfo, CertificateFixtures.testBody.toByteArray(), null)
    Assert.assertFalse(isValid)
  }

  @Test(expected = Exception::class)
  @Throws(Exception::class)
  fun test_validateSignature_ThrowsWhenKeyDoesNotMatch() {
    val codeSigningConfiguration = CodeSigningConfiguration(
      CertificateFixtures.testCertificate,
      mapOf(
        CODE_SIGNING_METADATA_KEY_ID_KEY to "test"
      ),
      false
    )
    val codesigningInfo = SignatureHeaderInfo.parseSignatureHeader("sig=\"aGVsbG8=\", keyid=\"other\"")
    codeSigningConfiguration.validateSignature(codesigningInfo, CertificateFixtures.testBody.toByteArray(), null)
  }

  @Test
  fun test_validateSignature_DoesNotUseChainInManifestResponseIfFlagIsFalse() {
    val codeSigningConfiguration = CodeSigningConfiguration(CertificateFixtures.testCertificate, mapOf(), false)
    val codesigningInfo = SignatureHeaderInfo.parseSignatureHeader(CertificateFixtures.testSignature)
    val isValid = codeSigningConfiguration.validateSignature(codesigningInfo, CertificateFixtures.testBody.toByteArray(), CertificateFixtures.testValidChainLeafCertificate + CertificateFixtures.testValidChainIntermediateCertificate)
    Assert.assertTrue(isValid)
  }

  @Test
  fun test_validateSignature_DoesUseChainInManifestResponseIfFlagIsTrue() {
    val codeSigningConfiguration = CodeSigningConfiguration(
      CertificateFixtures.testValidChainRootCertificate,
      mapOf(
        CODE_SIGNING_METADATA_KEY_ID_KEY to "ca-root"
      ),
      true
    )
    val codesigningInfo = SignatureHeaderInfo.parseSignatureHeader(CertificateFixtures.testValidChainLeafSignature)
    val isValid = codeSigningConfiguration.validateSignature(codesigningInfo, CertificateFixtures.testBody.toByteArray(), CertificateFixtures.testValidChainLeafCertificate + CertificateFixtures.testValidChainIntermediateCertificate)
    Assert.assertTrue(isValid)
  }
}
