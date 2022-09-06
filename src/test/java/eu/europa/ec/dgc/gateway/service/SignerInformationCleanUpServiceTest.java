/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 - 2022 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

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
        X509Certificate x509Certificate1 =
            CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "DE", "DETest1");
        X509Certificate x509Certificate2 =
            CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "DE", "DETest2");
        X509Certificate x509Certificate3 =
            CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "DE", "DETest3");

        SignerInformationEntity deleted3DaysAgo = createSignerInformationInDB("DE", null,
            certificateUtils.getCertThumbprint(x509Certificate2),
            Base64.getEncoder().encodeToString(x509Certificate1.getEncoded()),
            ZonedDateTime.now().minusDays(30), ZonedDateTime.now().minusDays(3));

        SignerInformationEntity deleted3WeeksAgo = createSignerInformationInDB("DE", null,
            certificateUtils.getCertThumbprint(x509Certificate3),
            Base64.getEncoder().encodeToString(x509Certificate1.getEncoded()),
            ZonedDateTime.now().minusDays(40), ZonedDateTime.now().minusDays(21));


        SignerInformationEntity notDeleted = createSignerInformationInDB("DE", "sig3",
            certificateUtils.getCertThumbprint(x509Certificate1),
            Base64.getEncoder().encodeToString(x509Certificate1.getEncoded()),
            ZonedDateTime.now().minusDays(40), null);

        underTest.cleanup();

        Assertions.assertEquals(2, signerInformationRepository.count());
        List<SignerInformationEntity> remaining = signerInformationRepository.findAll();
        Assertions.assertTrue(remaining.stream().anyMatch(it -> it.getId().equals(notDeleted.getId())));
        Assertions.assertTrue(remaining.stream().anyMatch(it -> it.getId().equals(deleted3DaysAgo.getId())));
        Assertions.assertFalse(remaining.stream().anyMatch(it -> it.getId().equals(deleted3WeeksAgo.getId())));
    }


    private SignerInformationEntity createSignerInformationInDB(String countryCode, String signature,
                                                                String thumbprint, String encoded,
                                                                ZonedDateTime createdAt, ZonedDateTime deletedAt)
        throws Exception {
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
