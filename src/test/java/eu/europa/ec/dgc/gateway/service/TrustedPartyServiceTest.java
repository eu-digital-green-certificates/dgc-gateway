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

import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedPartyRepository;
import eu.europa.ec.dgc.gateway.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.signing.SignedCertificateMessageBuilder;
import java.util.Optional;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class TrustedPartyServiceTest {

    @Autowired
    TrustedPartyRepository trustedPartyRepository;

    @Autowired
    TrustedPartyService trustedPartyService;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    DgcTestKeyStore dgcTestKeyStore;

    private static final String countryCode = "EU";

    @AfterEach
    void cleanUp() {
        // We have to delete all certs after each test because some tests are manipulating certs in DB.
        trustedPartyRepository.deleteAll();
    }

    @Test
    void trustedPartyServiceShouldReturnCertificate() throws Exception {
        String hash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        Optional<TrustedPartyEntity> certOptional = trustedPartyService.getCertificate(hash, countryCode, TrustedPartyEntity.CertificateType.UPLOAD);
        Assertions.assertTrue(certOptional.isPresent());
        Assertions.assertEquals(hash, certOptional.get().getThumbprint());

        hash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        certOptional = trustedPartyService.getCertificate(hash, countryCode, TrustedPartyEntity.CertificateType.CSCA);
        Assertions.assertTrue(certOptional.isPresent());
        Assertions.assertEquals(hash, certOptional.get().getThumbprint());

        hash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        certOptional = trustedPartyService.getCertificate(hash, countryCode, TrustedPartyEntity.CertificateType.AUTHENTICATION);
        Assertions.assertTrue(certOptional.isPresent());
        Assertions.assertEquals(hash, certOptional.get().getThumbprint());
    }

    @Test
    void trustedPartyServiceShouldNotReturnCertificateIfIntegrityOfRawDataIsViolated() throws Exception {
        Optional<TrustedPartyEntity> certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);

        Optional<TrustedPartyEntity> anotherCertOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode), countryCode, TrustedPartyEntity.CertificateType.AUTHENTICATION);

        Assertions.assertTrue(certOptional.isPresent());
        Assertions.assertTrue(anotherCertOptional.isPresent());

        TrustedPartyEntity cert = certOptional.get();
        cert.setRawData(anotherCertOptional.get().getRawData());

        trustedPartyRepository.save(cert);

        certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);
        Assertions.assertTrue(certOptional.isEmpty());
    }

    @Test
    void trustedPartyServiceShouldNotReturnCertificateIfIntegrityOfSignatureIsViolated() throws Exception {
        Optional<TrustedPartyEntity> certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);

        Optional<TrustedPartyEntity> anotherCertOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode), countryCode, TrustedPartyEntity.CertificateType.AUTHENTICATION);

        Assertions.assertTrue(certOptional.isPresent());
        Assertions.assertTrue(anotherCertOptional.isPresent());

        TrustedPartyEntity cert = certOptional.get();
        cert.setSignature(anotherCertOptional.get().getSignature());

        trustedPartyRepository.save(cert);

        certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);
        Assertions.assertTrue(certOptional.isEmpty());
    }

    @Test
    void trustedPartyServiceShouldNotReturnCertificateIfIntegrityOfThumbprintIsViolated() throws Exception {
        Optional<TrustedPartyEntity> certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);

        Optional<TrustedPartyEntity> anotherCertOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode), countryCode, TrustedPartyEntity.CertificateType.AUTHENTICATION);

        Assertions.assertTrue(certOptional.isPresent());
        Assertions.assertTrue(anotherCertOptional.isPresent());

        trustedPartyRepository.delete(anotherCertOptional.get());

        TrustedPartyEntity cert = certOptional.get();
        cert.setThumbprint(anotherCertOptional.get().getThumbprint());

        trustedPartyRepository.save(cert);

        certOptional = trustedPartyService.getCertificate(
            cert.getThumbprint(), countryCode, TrustedPartyEntity.CertificateType.CSCA);
        Assertions.assertTrue(certOptional.isEmpty());
    }

    @Test
    void trustedPartyServiceShouldNotReturnCertificateIfSignatureIsFromUnknownTrustAnchor() throws Exception {
        Optional<TrustedPartyEntity> certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);

        // Create new signature with a random non TrustAnchor certificate
        String newSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(new X509CertificateHolder(trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX").getEncoded()), trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "XX"))
            .withPayload(new X509CertificateHolder(trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode).getEncoded()))
            .buildAsString(true);

        Assertions.assertTrue(certOptional.isPresent());

        TrustedPartyEntity trustedPartyEntity = certOptional.get();
        trustedPartyEntity.setSignature(newSignature);
        trustedPartyRepository.save(trustedPartyEntity);

        certOptional = trustedPartyService.getCertificate(trustedPartyEntity.getThumbprint(), countryCode, TrustedPartyEntity.CertificateType.CSCA);
        Assertions.assertTrue(certOptional.isEmpty());
    }
}
