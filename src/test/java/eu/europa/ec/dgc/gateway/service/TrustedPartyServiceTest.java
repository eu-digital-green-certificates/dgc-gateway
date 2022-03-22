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
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.signing.SignedCertificateMessageBuilder;
import java.time.ZonedDateTime;
import java.util.List;
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

    private static final String countryCode = "EU";

    private static final ZonedDateTime now = ZonedDateTime.now();
    private static final ZonedDateTime nowMinusOneMinute = ZonedDateTime.now().minusMinutes(1);
    private static final ZonedDateTime nowMinusOneHour = ZonedDateTime.now().minusHours(1);
    private static final int TEST_CERTIFICATE_LIST_SIZE = 12;

    @AfterEach
    void cleanUp() {
        // We have to delete all certs after each test because some tests are manipulating certs in DB.
        trustedPartyRepository.deleteAll();
    }

    @Test
    void testSuccessfulGetTrustedPartyListIsSincePageable() throws Exception {
        cleanUp();
        long trustedPartyEntitiesInDb = trustedPartyRepository.count();
        prepareTestTrustedParty();
        Assertions.assertEquals(trustedPartyEntitiesInDb + TEST_CERTIFICATE_LIST_SIZE, trustedPartyRepository.count());

        List<TrustedPartyEntity> trustedPartyEntities =
            trustedPartyService.getCertificates(null, null, null);
        Assertions.assertEquals(TEST_CERTIFICATE_LIST_SIZE, trustedPartyEntities.size());

        List<TrustedPartyEntity> trustedPartyEntities3 =
            trustedPartyService.getCertificates( nowMinusOneMinute, null, null);
        Assertions.assertEquals(TEST_CERTIFICATE_LIST_SIZE /2, trustedPartyEntities3.size());

        List<TrustedPartyEntity> trustedPartyEntities4 =
            trustedPartyService.getCertificates(null, 0, 10);
        Assertions.assertEquals(10, trustedPartyEntities4.size());

        List<TrustedPartyEntity> trustedPartyEntities5 =
            trustedPartyService.getCertificates(null, 0, 100);
        Assertions.assertEquals(TEST_CERTIFICATE_LIST_SIZE, trustedPartyEntities5.size());

        List<TrustedPartyEntity> trustedPartyEntities6 =
            trustedPartyService.getCertificates(null, 1, 10);
        Assertions.assertEquals(2, trustedPartyEntities6.size());

        List<TrustedPartyEntity> trustedPartyEntities7 =
            trustedPartyService.getCertificates(null, 2, 10);
        Assertions.assertEquals(0, trustedPartyEntities7.size());

        List<TrustedPartyEntity> trustedPartyEntities8 =
            trustedPartyService.getCertificates( nowMinusOneMinute, 0, 10);
        Assertions.assertEquals(TEST_CERTIFICATE_LIST_SIZE /2, trustedPartyEntities8.size());

        List<TrustedPartyEntity> trustedPartyEntities9 =
            trustedPartyService.getCertificates( nowMinusOneMinute, 1, 10);
        Assertions.assertEquals(0, trustedPartyEntities9.size());
    }

    @Test
    void testSuccessfulGetTrustedPartyListByTypeAndCountryIsSincePageable() throws Exception {
        cleanUp();
        long trustedPartyEntitiesInDb = trustedPartyRepository.count();
        prepareTestTrustedParty();
        Assertions.assertEquals(trustedPartyEntitiesInDb + TEST_CERTIFICATE_LIST_SIZE,
            trustedPartyRepository.count());

        List<TrustedPartyEntity> trustedPartyEntities =
            trustedPartyService.getCertificates(TrustedPartyEntity.CertificateType.UPLOAD,
                null, null, null);
        Assertions.assertEquals(4, trustedPartyEntities.size());

        List<TrustedPartyEntity> trustedPartyEntities3 =
            trustedPartyService.getCertificates(TrustedPartyEntity.CertificateType.CSCA,
                nowMinusOneMinute, null, null);
        Assertions.assertEquals(2, trustedPartyEntities3.size());

        List<TrustedPartyEntity> trustedPartyEntities4 =
            trustedPartyService.getCertificates(countryCode, TrustedPartyEntity.CertificateType.UPLOAD,
                null, 0, 10);
        Assertions.assertEquals(2, trustedPartyEntities4.size());

        List<TrustedPartyEntity> trustedPartyEntities5 =
            trustedPartyService.getCertificates(countryCode, TrustedPartyEntity.CertificateType.UPLOAD,
                null, 1, 10);
        Assertions.assertEquals(0, trustedPartyEntities5.size());

        List<TrustedPartyEntity> trustedPartyEntities6 =
            trustedPartyService.getCertificates(countryCode, TrustedPartyEntity.CertificateType.CSCA,
                nowMinusOneMinute, 0, 10);
        Assertions.assertEquals(1, trustedPartyEntities6.size());

        List<TrustedPartyEntity> trustedPartyEntities7 =
            trustedPartyService.getCertificates(countryCode, TrustedPartyEntity.CertificateType.CSCA,
                nowMinusOneMinute, 1, 10);
        Assertions.assertEquals(0, trustedPartyEntities7.size());
    }

    @Test
    void testFailedGetTrustedPartyListIsSincePageable() {
        Assertions.assertThrows(IllegalArgumentException.class, () ->
            trustedPartyService.getCertificates(countryCode, TrustedPartyEntity.CertificateType.CSCA,
                null,-1,2));

        Assertions.assertThrows(IllegalArgumentException.class, () ->
            trustedPartyService.getCertificates(null, 0, 0));

        Assertions.assertThrows(IllegalArgumentException.class, () ->
            trustedPartyService.getCertificates(null, -1, 0));
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

    private void prepareTestTrustedParty() throws Exception {
        trustedPartyTestHelper.getTestCert("test1", TrustedPartyEntity.CertificateType.UPLOAD, "DE", now);
        trustedPartyTestHelper.getTestCert("test2", TrustedPartyEntity.CertificateType.CSCA, "DE", now);
        trustedPartyTestHelper.getTestCert("test3", TrustedPartyEntity.CertificateType.AUTHENTICATION, "DE", now);
        trustedPartyTestHelper.getTestCert("test4", TrustedPartyEntity.CertificateType.UPLOAD, "DE", nowMinusOneHour);
        trustedPartyTestHelper.getTestCert("test5", TrustedPartyEntity.CertificateType.CSCA, "DE", nowMinusOneHour);
        trustedPartyTestHelper.getTestCert("test6", TrustedPartyEntity.CertificateType.AUTHENTICATION, "DE", nowMinusOneHour);
        trustedPartyTestHelper.getTestCert("test7", TrustedPartyEntity.CertificateType.UPLOAD, "EU", now);
        trustedPartyTestHelper.getTestCert("test8", TrustedPartyEntity.CertificateType.CSCA, "EU", now);
        trustedPartyTestHelper.getTestCert("test9", TrustedPartyEntity.CertificateType.AUTHENTICATION, "EU", now);
        trustedPartyTestHelper.getTestCert("test10", TrustedPartyEntity.CertificateType.UPLOAD, "EU", nowMinusOneHour);
        trustedPartyTestHelper.getTestCert("test11", TrustedPartyEntity.CertificateType.CSCA, "EU", nowMinusOneHour);
        trustedPartyTestHelper.getTestCert("test12", TrustedPartyEntity.CertificateType.AUTHENTICATION, "EU", nowMinusOneHour);
    }

}
