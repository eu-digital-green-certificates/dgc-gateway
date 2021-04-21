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

import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedPartyRepository;
import eu.europa.ec.dgc.gateway.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@Slf4j
@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = DgcTestKeyStore.class)
public class TrustedPartyServiceTest {

    @Autowired
    TrustedPartyRepository trustedPartyRepository;

    @Autowired
    TrustedPartyService trustedPartyService;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    private static final String countryCode = "EU";

    @After
    public void cleanUp() {
        // We have to delete all certs after each test because some tests are manipulating certs in DB.
        trustedPartyRepository.deleteAll();
    }

    @Test
    public void trustedPartyServiceShouldReturnCertificate() throws Exception {
        String hash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        Optional<TrustedPartyEntity> certOptional = trustedPartyService.getCertificate(hash, countryCode, TrustedPartyEntity.CertificateType.UPLOAD);
        Assert.assertTrue(certOptional.isPresent());
        Assert.assertEquals(hash, certOptional.get().getThumbprint());

        hash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        certOptional = trustedPartyService.getCertificate(hash, countryCode, TrustedPartyEntity.CertificateType.CSCA);
        Assert.assertTrue(certOptional.isPresent());
        Assert.assertEquals(hash, certOptional.get().getThumbprint());

        hash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        certOptional = trustedPartyService.getCertificate(hash, countryCode, TrustedPartyEntity.CertificateType.AUTHENTICATION);
        Assert.assertTrue(certOptional.isPresent());
        Assert.assertEquals(hash, certOptional.get().getThumbprint());
    }

    @Test
    public void trustedPartyServiceShouldNotReturnCertificateIfIntegrityOfRawDataIsViolated() throws Exception {
        Optional<TrustedPartyEntity> certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);

        Optional<TrustedPartyEntity> anotherCertOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode), countryCode, TrustedPartyEntity.CertificateType.AUTHENTICATION);

        Assert.assertTrue(certOptional.isPresent());
        Assert.assertTrue(anotherCertOptional.isPresent());

        TrustedPartyEntity cert = certOptional.get();
        cert.setRawData(anotherCertOptional.get().getRawData());

        trustedPartyRepository.save(cert);

        certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);
        Assert.assertTrue(certOptional.isEmpty());
    }

    @Test
    public void trustedPartyServiceShouldNotReturnCertificateIfIntegrityOfSignatureIsViolated() throws Exception {
        Optional<TrustedPartyEntity> certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);

        Optional<TrustedPartyEntity> anotherCertOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode), countryCode, TrustedPartyEntity.CertificateType.AUTHENTICATION);

        Assert.assertTrue(certOptional.isPresent());
        Assert.assertTrue(anotherCertOptional.isPresent());

        TrustedPartyEntity cert = certOptional.get();
        cert.setSignature(anotherCertOptional.get().getSignature());

        trustedPartyRepository.save(cert);

        certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);
        Assert.assertTrue(certOptional.isEmpty());
    }

    @Test
    public void trustedPartyServiceShouldNotReturnCertificateIfIntegrityOfThumbprintIsViolated() throws Exception {
        Optional<TrustedPartyEntity> certOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.CSCA, countryCode), countryCode, TrustedPartyEntity.CertificateType.CSCA);

        Optional<TrustedPartyEntity> anotherCertOptional = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode), countryCode, TrustedPartyEntity.CertificateType.AUTHENTICATION);

        Assert.assertTrue(certOptional.isPresent());
        Assert.assertTrue(anotherCertOptional.isPresent());

        trustedPartyRepository.delete(anotherCertOptional.get());

        TrustedPartyEntity cert = certOptional.get();
        cert.setThumbprint(anotherCertOptional.get().getThumbprint());

        trustedPartyRepository.save(cert);

        certOptional = trustedPartyService.getCertificate(
            cert.getThumbprint(), countryCode, TrustedPartyEntity.CertificateType.CSCA);
        Assert.assertTrue(certOptional.isEmpty());
    }
}
