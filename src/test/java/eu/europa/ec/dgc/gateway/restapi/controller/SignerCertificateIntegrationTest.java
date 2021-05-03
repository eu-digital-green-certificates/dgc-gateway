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

package eu.europa.ec.dgc.gateway.restapi.controller;

import eu.europa.ec.dgc.gateway.repository.AuditEventRepository;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.gateway.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.signing.SignedCertificateMessageBuilder;
import eu.europa.ec.dgc.signing.SignedCertificateMessageParser;
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
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class SignerCertificateIntegrationTest {

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
    AuditEventRepository auditEventRepository;
    @Autowired
    private MockMvc mockMvc;

    private static final String countryCode = "EU";
    private static final String authCertSubject = "C=" + countryCode;

    @Test
    void testSuccessfulUpload() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        String payload = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayloadCertificate(new X509CertificateHolder(payloadCertificate.getEncoded()))
            .buildAsString();

        // immediately parse the message to get the signature from the signed message
        String signature = new SignedCertificateMessageParser(payload).getSignature();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        Assertions.assertEquals(signerInformationEntitiesInDb + 1, signerInformationRepository.count());
        Optional<SignerInformationEntity> createdSignerInformationEntity =
            signerInformationRepository.getFirstByThumbprint(certificateUtils.getCertThumbprint(payloadCertificate));

        Assertions.assertTrue(createdSignerInformationEntity.isPresent());

        Assertions.assertEquals(auditEventEntitiesInDb+1, auditEventRepository.count());
        Assertions.assertEquals(SignerInformationEntity.CertificateType.DSC, createdSignerInformationEntity.get().getCertificateType());
        Assertions.assertEquals(countryCode, createdSignerInformationEntity.get().getCountry());
        Assertions.assertEquals(signature, createdSignerInformationEntity.get().getSignature());
        Assertions.assertEquals(Base64.getEncoder().encodeToString(payloadCertificate.getEncoded()), createdSignerInformationEntity.get().getRawData());
    }

    @Test
    void testUploadFailedConflict() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        String payload = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayloadCertificate(new X509CertificateHolder(payloadCertificate.getEncoded()))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        mockMvc.perform(post("/signerCertificate/")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isConflict());
        Assertions.assertEquals(auditEventEntitiesInDb+1, auditEventRepository.count());
        Assertions.assertEquals(signerInformationEntitiesInDb + 1, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedInvalidCSCA() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        // sign with TrustAnchor
        X509Certificate cscaCertificate = dgcTestKeyStore.getTrustAnchor();
        PrivateKey cscaPrivateKey = dgcTestKeyStore.getTrustAnchorPrivateKey();

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        String payload = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayloadCertificate(new X509CertificateHolder(payloadCertificate.getEncoded()))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest());
        Assertions.assertEquals(auditEventEntitiesInDb+1, auditEventRepository.count());
        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedInvalidCSCAWrongCountryCode() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        // sign with CSCA from another country
        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "XX");
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, "XX");


        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        String payload = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayloadCertificate(new X509CertificateHolder(payloadCertificate.getEncoded()))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest());
        Assertions.assertEquals(auditEventEntitiesInDb+1, auditEventRepository.count());
        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedPayloadCertCountryWrong() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, "XX", "Payload Cert", cscaCertificate, cscaPrivateKey);

        String payload = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayloadCertificate(new X509CertificateHolder(payloadCertificate.getEncoded()))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest());
        Assertions.assertEquals(auditEventEntitiesInDb+1, auditEventRepository.count());
        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedWrongSignerCertificate() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX");
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        String payload = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayloadCertificate(new X509CertificateHolder(payloadCertificate.getEncoded()))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest());
        Assertions.assertEquals(auditEventEntitiesInDb+1, auditEventRepository.count());
        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedInvalidCmsMessage() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        String payload = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayloadCertificate(new X509CertificateHolder(payloadCertificate.getEncoded()))
            .buildAsString();

        // randomly play a little bit inside the base64 string
        payload = payload.replace(payload.substring(10, 50), payload.substring(80, 120));

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest());
        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

}
