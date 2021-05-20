/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
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

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.gateway.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SignerInformationServiceTest {

    @Autowired
    DgcConfigProperties dgcConfigProperties;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore dgcTestKeyStore;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    SignerInformationRepository signerInformationRepository;

    @Autowired
    SignerInformationService signerInformationService;

    private static final String countryCode = "EU";
    private static final String dummySignature = "randomStringAsSignatureWhichIsNotValidatedInServiceLevel";

    @Test
    void testSuccessfulAddingNewSignerInformationAndDelete() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        signerInformationService.addSignerCertificate(
            new X509CertificateHolder(payloadCertificate.getEncoded()),
            new X509CertificateHolder(signerCertificate.getEncoded()),
            dummySignature,
            countryCode
        );

        Assertions.assertEquals(signerInformationEntitiesInDb + 1, signerInformationRepository.count());
        Optional<SignerInformationEntity> createdSignerInformationEntity =
            signerInformationRepository.getFirstByThumbprint(certificateUtils.getCertThumbprint(payloadCertificate));

        Assertions.assertTrue(createdSignerInformationEntity.isPresent());

        Assertions.assertEquals(SignerInformationEntity.CertificateType.DSC, createdSignerInformationEntity.get().getCertificateType());
        Assertions.assertEquals(countryCode, createdSignerInformationEntity.get().getCountry());
        Assertions.assertEquals(dummySignature, createdSignerInformationEntity.get().getSignature());
        Assertions.assertEquals(Base64.getEncoder().encodeToString(payloadCertificate.getEncoded()), createdSignerInformationEntity.get().getRawData());

        signerInformationService.deleteSignerCertificate(
            new X509CertificateHolder(payloadCertificate.getEncoded()),
            new X509CertificateHolder(signerCertificate.getEncoded()),
            countryCode
        );

        Optional<SignerInformationEntity> deletedSignerInformationEntity =
            signerInformationRepository.getFirstByThumbprint(certificateUtils.getCertThumbprint(payloadCertificate));

        Assertions.assertTrue(deletedSignerInformationEntity.isEmpty());
        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testAddingFailedConflict() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        signerInformationService.addSignerCertificate(
            new X509CertificateHolder(payloadCertificate.getEncoded()),
            new X509CertificateHolder(signerCertificate.getEncoded()),
            dummySignature,
            countryCode
        );

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.ALREADY_EXIST_CHECK_FAILED, e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb + 1, signerInformationRepository.count());
    }

    @Test
    void testAddingFailedKidConflict() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        signerInformationService.addSignerCertificate(
            new X509CertificateHolder(payloadCertificate.getEncoded()),
            new X509CertificateHolder(signerCertificate.getEncoded()),
            dummySignature,
            countryCode
        );

        Optional<SignerInformationEntity> certInDbOptional = signerInformationRepository.getFirstByThumbprint(certificateUtils.getCertThumbprint(payloadCertificate));

        Assertions.assertTrue(certInDbOptional.isPresent());

        SignerInformationEntity certInDb = certInDbOptional.get();
        certInDb.setThumbprint(certInDb.getThumbprint().substring(0, 40) + "x".repeat(24)); // Generate new Hash with first 40 chars from ogirinal hash and add 24 x

        signerInformationRepository.save(certInDb);

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.KID_CHECK_FAILED, e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb + 1, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedInvalidCSCA() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        // sign with TrustAnchor
        X509Certificate cscaCertificate = dgcTestKeyStore.getTrustAnchor();
        PrivateKey cscaPrivateKey = dgcTestKeyStore.getTrustAnchorPrivateKey();

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.CSCA_CHECK_FAILED, e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedInvalidCSCAWrongCountryCode() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        // sign with CSCA from another country
        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "XX");
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, "XX");


        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.CSCA_CHECK_FAILED, e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedPayloadCertCountryWrong() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, "XX", "Payload Cert", cscaCertificate, cscaPrivateKey);

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED, e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedWrongSignerCertificate() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.UPLOADER_CERT_CHECK_FAILED, e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testDeleteFailedNotExists() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        try {
            signerInformationService.deleteSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.EXIST_CHECK_FAILED, e.getReason());
        }
    }

    @Test
    void testDeleteFailedPayloadCertCountryWrong() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, "XX", "Payload Cert", cscaCertificate, cscaPrivateKey);

        try {
            signerInformationService.deleteSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED, e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testDeleteFailedWrongSignerCertificate() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        try {
            signerInformationService.deleteSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.UPLOADER_CERT_CHECK_FAILED, e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }
}
