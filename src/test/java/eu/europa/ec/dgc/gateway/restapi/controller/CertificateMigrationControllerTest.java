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

package eu.europa.ec.dgc.gateway.restapi.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.ser.ZonedDateTimeSerializer;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.connector.model.ValidationRule;
import eu.europa.ec.dgc.gateway.entity.RevocationBatchEntity;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.entity.ValidationRuleEntity;
import eu.europa.ec.dgc.gateway.repository.RevocationBatchRepository;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.repository.ValidationRuleRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.CmsPackageDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationBatchDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationHashTypeDto;
import eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.signing.SignedCertificateMessageBuilder;
import eu.europa.ec.dgc.signing.SignedCertificateMessageParser;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.utils.CertificateUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatterBuilder;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils.getDummyValidationRule;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class CertificateMigrationControllerTest {


    @Autowired
    DgcConfigProperties dgcConfigProperties;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    RevocationBatchRepository revocationBatchRepository;

    @Autowired
    SignerInformationRepository signerInformationRepository;

    @Autowired
    ValidationRuleRepository validationRuleRepository;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    CertificateUtils certificateUtils;


    ObjectMapper objectMapper;

    private static final String countryCode = "EU";
    private static final String authCertSubject = "C=" + countryCode;

    @BeforeEach
    void setUp() {
        signerInformationRepository.deleteAll();
        revocationBatchRepository.deleteAll();
        validationRuleRepository.deleteAll();
        objectMapper = new ObjectMapper();

        JavaTimeModule javaTimeModule = new JavaTimeModule();
        javaTimeModule.addSerializer(ZonedDateTime.class, new ZonedDateTimeSerializer(
                new DateTimeFormatterBuilder().appendPattern("yyyy-MM-dd'T'HH:mm:ssXXX").toFormatter()
        ));

        objectMapper.registerModule(javaTimeModule);
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Test
    void testAllCertTypes() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ec");
        X509Certificate certDscEu = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), countryCode, "Test");
        String cmsBase64 = Base64.getEncoder().encodeToString(certDscEu.getEncoded());

        createSignerInfo(cmsBase64, certDscEu, "signature1");
        createRevocation("id1", cmsBase64, false);
        createValidationEntry(cmsBase64);

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/cms-migration")
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject))
                .andExpect(jsonPath("$", hasSize(3)))
                .andExpect(jsonPath("$[0].type", is(CmsPackageDto.CmsPackageTypeDto.DSC.name())))
                .andExpect(jsonPath("$[0].cms", is("signature1")))
                .andExpect(jsonPath("$[1].type", is(CmsPackageDto.CmsPackageTypeDto.REVOCATION_LIST.name())))
                .andExpect(jsonPath("$[1].cms", is(cmsBase64)))
                .andExpect(jsonPath("$[2].type", is(CmsPackageDto.CmsPackageTypeDto.VALIDATION_RULE.name())))
                .andExpect(jsonPath("$[2].cms", is(cmsBase64)));
    }

    @Test
    void testRevocationDeleted() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ec");
        X509Certificate certDscEu = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), countryCode, "Test");
        String cmsBase64 = Base64.getEncoder().encodeToString(certDscEu.getEncoded());

        createRevocation("id1", null, true);
        RevocationBatchEntity entity = createRevocation("id2", cmsBase64, false);

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/cms-migration")
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject))
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].entityId", is(entity.getId()), Long.class))
                .andExpect(jsonPath("$[0].cms", is(cmsBase64)));
    }

    @Test
    void testNoneForCountry() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/cms-migration")
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject))
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void testUpdateDSC() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        String existingPayload = new SignedCertificateMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(new X509CertificateHolder(payloadCertificate.getEncoded()))
                .buildAsString();
        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(existingPayload);
        SignerInformationEntity existingEntity = createSignerInfoEntity(existingPayload, parser.getSignature(), certificateUtils.getCertThumbprint(payloadCertificate));

        trustedPartyTestHelper.clear(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        trustedPartyTestHelper.clear(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        X509Certificate signerCertificateUpdate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKeyUpdate = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate cscaCertificateUpdate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKeyUpdate = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPairUpdate = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificateUpdate = CertificateTestUtils.generateCertificate(payloadKeyPairUpdate, countryCode, "Payload Cert", cscaCertificateUpdate, cscaPrivateKeyUpdate);

        String updatePayload = new SignedCertificateMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificateUpdate), signerPrivateKeyUpdate)
                .withPayload(new X509CertificateHolder(payloadCertificateUpdate.getEncoded()))
                .buildAsString();
        String updatedSignature = new SignedCertificateMessageParser(updatePayload).getSignature();
        CmsPackageDto dto = new CmsPackageDto(updatePayload, existingEntity.getId(), CmsPackageDto.CmsPackageTypeDto.DSC);


        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isNoContent());

        Optional<SignerInformationEntity> updatedCert = signerInformationRepository.findById(existingEntity.getId());

        Assertions.assertTrue(updatedCert.isPresent());
        Assertions.assertEquals(Base64.getEncoder().encodeToString(payloadCertificateUpdate.getEncoded()), updatedCert.get().getRawData());
        Assertions.assertEquals(updatedSignature, updatedCert.get().getSignature());
    }

    @Test
    void testUpdateDSCNotFound() throws Exception {
        X509Certificate signerCertificateUpdate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKeyUpdate = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate cscaCertificateUpdate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKeyUpdate = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPairUpdate = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificateUpdate = CertificateTestUtils.generateCertificate(payloadKeyPairUpdate, countryCode, "Payload Cert", cscaCertificateUpdate, cscaPrivateKeyUpdate);

        String updatePayload = new SignedCertificateMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificateUpdate), signerPrivateKeyUpdate)
                .withPayload(new X509CertificateHolder(payloadCertificateUpdate.getEncoded()))
                .buildAsString();
        CmsPackageDto dto = new CmsPackageDto(updatePayload, 404L, CmsPackageDto.CmsPackageTypeDto.DSC);

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code", is("0x010")));
    }

    @Test
    void testUpdateDSCCMSinvalid() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate, cscaPrivateKey);

        String existingPayload = new SignedCertificateMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(new X509CertificateHolder(payloadCertificate.getEncoded()))
                .buildAsString();
        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(existingPayload);
        SignerInformationEntity existingEntity = createSignerInfoEntity(existingPayload, parser.getSignature(), certificateUtils.getCertThumbprint(payloadCertificate));

        CmsPackageDto dto = new CmsPackageDto("invalidCMS", existingEntity.getId(), CmsPackageDto.CmsPackageTypeDto.DSC);

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code", is("0x260")));
    }

    @Test
    void testUpdateValidationRule() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        trustedPartyTestHelper.clear(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate signerCertificate2 = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey2 = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        String payload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(validationRule))
                .buildAsString();
        ValidationRuleEntity entity = createValidationEntry(payload);
        String updatePayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate2), signerPrivateKey2)
                .withPayload(objectMapper.writeValueAsString(validationRule))
                .buildAsString();
        CmsPackageDto dto = new CmsPackageDto(updatePayload, entity.getId(), CmsPackageDto.CmsPackageTypeDto.VALIDATION_RULE);

        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isNoContent());

        Optional<ValidationRuleEntity> updatedRule =
                validationRuleRepository.findById(entity.getId());

        Assertions.assertTrue(updatedRule.isPresent());
        Assertions.assertEquals(updatePayload, updatedRule.get().getCms());
    }

    @Test
    void testUpdateValidationRulePayloadNotMatching() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        trustedPartyTestHelper.clear(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate signerCertificate2 = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey2 = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        String existingPayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(validationRule))
                .buildAsString();
        ValidationRuleEntity entity = createValidationEntry(existingPayload);

        validationRule.setIdentifier("MISMATCH");
        String updatePayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate2), signerPrivateKey2)
                .withPayload(objectMapper.writeValueAsString(validationRule))
                .buildAsString();
        CmsPackageDto dto = new CmsPackageDto(updatePayload, entity.getId(), CmsPackageDto.CmsPackageTypeDto.VALIDATION_RULE);

        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code", is("0x032")));

        Optional<ValidationRuleEntity> updatedRule =
                validationRuleRepository.findById(entity.getId());

        Assertions.assertTrue(updatedRule.isPresent());
        Assertions.assertEquals(existingPayload, updatedRule.get().getCms());
    }

    @Test
    void testUpdateValidationRulePayloadNotFound() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        validationRule.setIdentifier("MISMATCH");
        String updatePayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(validationRule))
                .buildAsString();
        CmsPackageDto dto = new CmsPackageDto(updatePayload, 404L, CmsPackageDto.CmsPackageTypeDto.VALIDATION_RULE);

        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code", is("0x030")));
    }

    @Test
    void testUpdateValidationRuleInvalidCMS() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        String existingPayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(validationRule))
                .buildAsString();
        ValidationRuleEntity entity = createValidationEntry(existingPayload);
        CmsPackageDto dto = new CmsPackageDto("invalidCms", entity.getId(), CmsPackageDto.CmsPackageTypeDto.VALIDATION_RULE);

        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code", is("0x260")));
    }

    @Test
    void testUpdateValidationRuleWrongCountry() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "DE");
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "DE");
        trustedPartyTestHelper.clear(TrustedPartyEntity.CertificateType.UPLOAD, "DE");
        X509Certificate signerCertificate2 = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey2 = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        String existingPayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(validationRule))
                .buildAsString();
        ValidationRuleEntity entity = createValidationEntry(existingPayload, "DE");

        String updatePayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate2), signerPrivateKey2)
                .withPayload(objectMapper.writeValueAsString(validationRule))
                .buildAsString();
        CmsPackageDto dto = new CmsPackageDto(updatePayload, entity.getId(), CmsPackageDto.CmsPackageTypeDto.VALIDATION_RULE);

        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code", is("0x031")));

        Optional<ValidationRuleEntity> updatedRule =
                validationRuleRepository.findById(entity.getId());

        Assertions.assertTrue(updatedRule.isPresent());
        Assertions.assertEquals(existingPayload, updatedRule.get().getCms());
    }

    @Test
    void testUpdateRevocation() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        trustedPartyTestHelper.clear(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate signerCertificate2 = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey2 = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash2 = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        RevocationBatchDto revocationBatch = createRevocationBatch("kid1");

        String existingPayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(revocationBatch))
                .buildAsString();
        RevocationBatchEntity entity = createRevocationBatchEntity(existingPayload);

        String updatePayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate2), signerPrivateKey2)
                .withPayload(objectMapper.writeValueAsString(revocationBatch))
                .buildAsString();
        CmsPackageDto dto = new CmsPackageDto(updatePayload, entity.getId(), CmsPackageDto.CmsPackageTypeDto.REVOCATION_LIST);


        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash2)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isNoContent());

        Optional<RevocationBatchEntity> updatedBatch =
                revocationBatchRepository.findById(entity.getId());

        Assertions.assertTrue(updatedBatch.isPresent());
        Assertions.assertEquals(updatePayload, updatedBatch.get().getSignedBatch());
    }

    @Test
    void testUpdateRevocationPayloadNotMatching() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        trustedPartyTestHelper.clear(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate signerCertificate2 = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey2 = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash2 = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        RevocationBatchDto revocationBatch = createRevocationBatch("kid1");

        String existingPayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(revocationBatch))
                .buildAsString();
        RevocationBatchEntity entity = createRevocationBatchEntity(existingPayload);

        RevocationBatchDto revocationBatchUnmatch = createRevocationBatch("kid2");

        String updatePayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate2), signerPrivateKey2)
                .withPayload(objectMapper.writeValueAsString(revocationBatchUnmatch))
                .buildAsString();
        CmsPackageDto dto = new CmsPackageDto(updatePayload, entity.getId(), CmsPackageDto.CmsPackageTypeDto.REVOCATION_LIST);


        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash2)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code", is("0x022")));

        Optional<RevocationBatchEntity> updatedBatch =
                revocationBatchRepository.findById(entity.getId());

        Assertions.assertTrue(updatedBatch.isPresent());
        Assertions.assertEquals(existingPayload, updatedBatch.get().getSignedBatch());
    }

    @Test
    void testUpdateRevocationPayloadNotFound() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        RevocationBatchDto revocationBatch = createRevocationBatch("kid1");

        String updatePayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(revocationBatch))
                .buildAsString();
        CmsPackageDto dto = new CmsPackageDto(updatePayload, 404L, CmsPackageDto.CmsPackageTypeDto.REVOCATION_LIST);


        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code", is("0x020")));
    }

    @Test
    void testUpdateRevocationInvalidCMS() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        RevocationBatchDto revocationBatch = createRevocationBatch("kid1");

        String existingPayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(revocationBatch))
                .buildAsString();
        RevocationBatchEntity entity = createRevocationBatchEntity(existingPayload);

        CmsPackageDto dto = new CmsPackageDto("invalidCms", entity.getId(), CmsPackageDto.CmsPackageTypeDto.REVOCATION_LIST);

        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code", is("0x260")));

        Optional<RevocationBatchEntity> updatedBatch =
                revocationBatchRepository.findById(entity.getId());

        Assertions.assertTrue(updatedBatch.isPresent());
        Assertions.assertEquals(existingPayload, updatedBatch.get().getSignedBatch());
    }

    @Test
    void testUpdateRevocationWrongCountry() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "DE");
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "DE");
        trustedPartyTestHelper.clear(TrustedPartyEntity.CertificateType.UPLOAD, "DE");
        X509Certificate signerCertificate2 = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey2 = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash2 = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        RevocationBatchDto revocationBatch = createRevocationBatch("kid1");
        revocationBatch.setCountry("DE");

        String existingPayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(revocationBatch))
                .buildAsString();
        RevocationBatchEntity entity = createRevocationBatchEntity(existingPayload, "DE");

        String updatePayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate2), signerPrivateKey2)
                .withPayload(objectMapper.writeValueAsString(revocationBatch))
                .buildAsString();
        CmsPackageDto dto = new CmsPackageDto(updatePayload, entity.getId(), CmsPackageDto.CmsPackageTypeDto.REVOCATION_LIST);

        mockMvc.perform(post("/cms-migration")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(dto))
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash2)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code", is("0x021")));
    }

    private void createSignerInfo(final String cmsBase64, final X509Certificate certDscEu, final String signature) {
        signerInformationRepository.save(new SignerInformationEntity(
                null, ZonedDateTime.now(), null, countryCode, certificateUtils.getCertThumbprint(certDscEu),
                cmsBase64, signature, SignerInformationEntity.CertificateType.DSC
        ));
    }

    private RevocationBatchEntity createRevocation(final String batchId, final String cmsBase64, boolean deleted) {
        RevocationBatchEntity revocationBatchEntity = new RevocationBatchEntity(
                null, batchId, countryCode, ZonedDateTime.now(), ZonedDateTime.now().plusDays(2),
                deleted, RevocationBatchEntity.RevocationHashType.SIGNATURE, "UNKNOWN_KID", cmsBase64);
        return revocationBatchRepository.save(revocationBatchEntity);
    }

    private SignerInformationEntity createSignerInfoEntity(final String cms, final String signature, final String thumbprint) {
        SignerInformationEntity signerInformationEntity = new SignerInformationEntity();
        signerInformationEntity.setCertificateType(SignerInformationEntity.CertificateType.DSC);
        signerInformationEntity.setRawData(cms);
        signerInformationEntity.setSignature(signature);
        signerInformationEntity.setCountry(countryCode);
        signerInformationEntity.setCreatedAt(ZonedDateTime.now());
        signerInformationEntity.setThumbprint(thumbprint);
        return signerInformationRepository.save(signerInformationEntity);
    }

    private ValidationRuleEntity createValidationEntry(final String cms) {
        return createValidationEntry(cms, countryCode);
    }

    private ValidationRuleEntity createValidationEntry(final String cms, final String countryCode) {
        ValidationRuleEntity validationRuleEntity = new ValidationRuleEntity();
        validationRuleEntity.setRuleId("rule1");
        validationRuleEntity.setValidationRuleType(ValidationRuleEntity.ValidationRuleType.ACCEPTANCE);
        validationRuleEntity.setValidFrom(ZonedDateTime.now());
        validationRuleEntity.setValidTo(ZonedDateTime.now().plusDays(5));
        validationRuleEntity.setCountry(countryCode);
        validationRuleEntity.setCms(cms);
        validationRuleEntity.setVersion("1");
        validationRuleEntity.setCreatedAt(ZonedDateTime.now());
        return validationRuleRepository.save(validationRuleEntity);
    }

    private RevocationBatchEntity createRevocationBatchEntity(final String cms) {
        return createRevocationBatchEntity(cms, countryCode);
    }

    private RevocationBatchEntity createRevocationBatchEntity(final String cms, final String countryCode) {
        RevocationBatchEntity revocationBatchEntity = new RevocationBatchEntity();
        revocationBatchEntity.setBatchId("batch1");
        revocationBatchEntity.setCountry(countryCode);
        revocationBatchEntity.setKid("KID1");
        revocationBatchEntity.setChanged(ZonedDateTime.now());
        revocationBatchEntity.setExpires(ZonedDateTime.now().plusDays(5));
        revocationBatchEntity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        revocationBatchEntity.setSignedBatch(cms);
        return revocationBatchRepository.save(revocationBatchEntity);
    }

    private RevocationBatchDto createRevocationBatch(String kid) {
        RevocationBatchDto revocationBatchDto = new RevocationBatchDto();
        revocationBatchDto.setCountry(countryCode);
        revocationBatchDto.setExpires(ZonedDateTime.now().plusDays(7));
        revocationBatchDto.setHashType(RevocationHashTypeDto.SIGNATURE);
        revocationBatchDto.setKid(kid);
        revocationBatchDto.setEntries(List.of(
                new RevocationBatchDto.BatchEntryDto("aaaaaaaaaaaaaaaaaaaaaaaa"),
                new RevocationBatchDto.BatchEntryDto("bbbbbbbbbbbbbbbbbbbbbbbb"),
                new RevocationBatchDto.BatchEntryDto("cccccccccccccccccccccccc"),
                new RevocationBatchDto.BatchEntryDto("dddddddddddddddddddddddd"),
                new RevocationBatchDto.BatchEntryDto("eeeeeeeeeeeeeeeeeeeeeeee")
        ));
        return revocationBatchDto;
    }
}
