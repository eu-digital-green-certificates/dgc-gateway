package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.utils.CertificateUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;

@SpringBootTest(properties = "dgc.signer-information.delete-threshold=14")
@Slf4j
class SignerInformationCleanUpServiceTest {

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    SignerInformationRepository signerInformationRepository;

    @Autowired
    SignerInformationCleanUpService underTest;


    @BeforeEach
    public void setup() {
        signerInformationRepository.deleteAll();
    }


    @Test
    void testCleanup() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ec");

        SignerInformationEntity deleted3DaysAgo = createSignerInformationInDB("DE", null,
                null, null,
                ZonedDateTime.now().minusDays(30), ZonedDateTime.now().minusDays(3));

        SignerInformationEntity deleted3WeeksAgo = createSignerInformationInDB("DE", null,
                null, null,
                ZonedDateTime.now().minusDays(40), ZonedDateTime.now().minusDays(21));

        X509Certificate x509Certificate = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "DE", "DETest");

        SignerInformationEntity notDeleted = createSignerInformationInDB("DE", "sig3",
                certificateUtils.getCertThumbprint(x509Certificate), Base64.getEncoder().encodeToString(x509Certificate.getEncoded()),
                ZonedDateTime.now().minusDays(40), null);

        underTest.cleanup();

        Assertions.assertEquals(2, signerInformationRepository.count());
        List<SignerInformationEntity> remaining = signerInformationRepository.findAll();
        Assertions.assertTrue(remaining.stream().anyMatch(it -> it.getId().equals(notDeleted.getId())));
        Assertions.assertTrue(remaining.stream().anyMatch(it -> it.getId().equals(deleted3DaysAgo.getId())));
        Assertions.assertFalse(remaining.stream().anyMatch(it -> it.getId().equals(deleted3WeeksAgo.getId())));
    }



    private SignerInformationEntity createSignerInformationInDB(String countryCode, String signature,
                                             String thumbprint, String encoded, ZonedDateTime createdAt, ZonedDateTime deletedAt) throws Exception {
        return signerInformationRepository.save(new SignerInformationEntity(
                null,
                createdAt,
                deletedAt,
                countryCode,
                thumbprint,
                encoded,
                signature,
                SignerInformationEntity.CertificateType.DSC
        ));
    }
}