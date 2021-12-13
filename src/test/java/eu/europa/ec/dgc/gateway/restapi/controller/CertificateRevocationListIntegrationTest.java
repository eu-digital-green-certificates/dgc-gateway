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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.ser.ZonedDateTimeSerializer;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.RevocationBatchEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.AuditEventRepository;
import eu.europa.ec.dgc.gateway.repository.RevocationBatchRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.BatchDeleteRequestDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.BatchDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.HashTypeDto;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.signing.SignedStringMessageParser;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatterBuilder;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@Slf4j
class CertificateRevocationListIntegrationTest {

    @Autowired
    DgcConfigProperties dgcConfigProperties;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    AuditEventRepository auditEventRepository;

    @Autowired
    RevocationBatchRepository revocationBatchRepository;

    ObjectMapper objectMapper;

    @Autowired
    private MockMvc mockMvc;

    private static final String countryCode = "EU";
    private static final String authCertSubject = "C=" + countryCode;

    @BeforeEach
    public void setup() {
        revocationBatchRepository.deleteAll();
        auditEventRepository.deleteAll();

        objectMapper = new ObjectMapper();

        JavaTimeModule javaTimeModule = new JavaTimeModule();
        javaTimeModule.addSerializer(ZonedDateTime.class, new ZonedDateTimeSerializer(
            new DateTimeFormatterBuilder().appendPattern("yyyy-MM-dd'T'HH:mm:ssXXX").toFormatter()
        ));

        objectMapper.registerModule(javaTimeModule);
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    }

    @Test
    void testSuccessfulUpload() throws Exception {
        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        BatchDto batchDto = new BatchDto();
        batchDto.setCountry(countryCode);
        batchDto.setExpires(ZonedDateTime.now().plusDays(7));
        batchDto.setHashType(HashTypeDto.SIGNATURE);
        batchDto.setKid("UNKNOWN_KID");
        batchDto.setEntries(List.of(
            new BatchDto.BatchEntryDto("aaaaaaaaaaaaaaaaaaaaaaaa"),
            new BatchDto.BatchEntryDto("bbbbbbbbbbbbbbbbbbbbbbbb"),
            new BatchDto.BatchEntryDto("cccccccccccccccccccccccc"),
            new BatchDto.BatchEntryDto("dddddddddddddddddddddddd"),
            new BatchDto.BatchEntryDto("eeeeeeeeeeeeeeeeeeeeeeee")
        ));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(batchDto))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isCreated());

        Assertions.assertEquals(revocationBatchesInDb + 1, revocationBatchRepository.count());
        Optional<RevocationBatchEntity> createdRevocationBatch =
            revocationBatchRepository.findAll().stream().findFirst();

        Assertions.assertTrue(createdRevocationBatch.isPresent());

        Assertions.assertEquals(auditEventEntitiesInDb + 1, auditEventRepository.count());
        Assertions.assertEquals(batchDto.getExpires().toEpochSecond(), createdRevocationBatch.get().getExpires().toEpochSecond());
        Assertions.assertTrue(
            ZonedDateTime.now().toEpochSecond() - 2 < createdRevocationBatch.get().getChanged().toEpochSecond()
                && ZonedDateTime.now().toEpochSecond() + 2 > createdRevocationBatch.get().getChanged().toEpochSecond());
        Assertions.assertEquals(countryCode, createdRevocationBatch.get().getCountry());
        Assertions.assertEquals(batchDto.getHashType().name(), createdRevocationBatch.get().getType().name());
        Assertions.assertEquals(batchDto.getKid(), createdRevocationBatch.get().getKid());
        Assertions.assertEquals(36, createdRevocationBatch.get().getBatchId().length());

        SignedStringMessageParser parser = new SignedStringMessageParser(createdRevocationBatch.get().getSignedBatch());
        BatchDto parsedRevocationBatch = objectMapper.readValue(parser.getPayload(), BatchDto.class);

        assertEquals(batchDto, parsedRevocationBatch);
    }

    @Test
    void testUploadFailedInvalidJson() throws Exception {
        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload("randomBadString")
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testUploadFailedInvalidJsonValues() throws Exception {
        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        BatchDto batchDto = new BatchDto();
        batchDto.setCountry(countryCode);
        batchDto.setExpires(ZonedDateTime.now().plusDays(7));
        batchDto.setHashType(HashTypeDto.SIGNATURE);
        batchDto.setKid("KIDWHICHISWAYTOLONGTOPASS");
        batchDto.setEntries(List.of(
            new BatchDto.BatchEntryDto("aaaaaaaaaaaaaaaaaaaaaaaa"),
            new BatchDto.BatchEntryDto("bbbbbbbbbbbbbbbbbbbbbbbb"),
            new BatchDto.BatchEntryDto("cccccccccccccccccccccccc"),
            new BatchDto.BatchEntryDto("dddddddddddddddddddddddd"),
            new BatchDto.BatchEntryDto("eeeeeeeeeeeeeeeeeeeeeeee")
        ));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(batchDto))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testUploadFailedInvalidJsonValuesInHashEntries() throws Exception {
        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        BatchDto batchDto = new BatchDto();
        batchDto.setCountry(countryCode);
        batchDto.setExpires(ZonedDateTime.now().plusDays(7));
        batchDto.setHashType(HashTypeDto.SIGNATURE);
        batchDto.setKid("UNKNOWN_KID");
        batchDto.setEntries(List.of(
            new BatchDto.BatchEntryDto("aaaaaaaaaaaaaaaaaaaaaaaa"),
            new BatchDto.BatchEntryDto("bbbbbbbbbbbbbbbbbbbbbbbb"),
            new BatchDto.BatchEntryDto("ccccccccccccccccccccccccA"),
            new BatchDto.BatchEntryDto("dddddddddddddddddddddddd"),
            new BatchDto.BatchEntryDto("eeeeeeeeeeeeeeeeeeeeeeee")
        ));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(batchDto))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testUploadFailedInvalidCountry() throws Exception {
        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        BatchDto batchDto = new BatchDto();
        batchDto.setCountry("XX");
        batchDto.setExpires(ZonedDateTime.now().plusDays(7));
        batchDto.setHashType(HashTypeDto.SIGNATURE);
        batchDto.setKid("UNKNOWN_KID");
        batchDto.setEntries(List.of(
            new BatchDto.BatchEntryDto("aaaaaaaaaaaaaaaaaaaaaaaa"),
            new BatchDto.BatchEntryDto("bbbbbbbbbbbbbbbbbbbbbbbb"),
            new BatchDto.BatchEntryDto("cccccccccccccccccccccccc"),
            new BatchDto.BatchEntryDto("dddddddddddddddddddddddd"),
            new BatchDto.BatchEntryDto("eeeeeeeeeeeeeeeeeeeeeeee")
        ));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(batchDto))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isForbidden());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testDeleteRevocationBatch() throws Exception {
        testSuccessfulUpload();

        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        BatchDeleteRequestDto deleteRequestDto = new BatchDeleteRequestDto(
            revocationBatchRepository.findAll().get(0).getBatchId()
        );

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isNoContent());

        Assertions.assertEquals(revocationBatchesInDb - 1, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb + 1, auditEventRepository.count());
    }


    @Test
    void testDeleteRevocationBatchAlternativeEndpoint() throws Exception {
        testSuccessfulUpload();

        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        BatchDeleteRequestDto deleteRequestDto = new BatchDeleteRequestDto(
            revocationBatchRepository.findAll().get(0).getBatchId()
        );

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/revocation-list/delete")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isNoContent());

        Assertions.assertEquals(revocationBatchesInDb - 1, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb + 1, auditEventRepository.count());
    }

    @Test
    void testDeleteRevocationBatchFailedInvalidJson() throws Exception {
        testSuccessfulUpload();

        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload("randomString")
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testDeleteRevocationBatchFailedInvalidJsonValue() throws Exception {
        testSuccessfulUpload();

        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(new BatchDeleteRequestDto("ThisIsNotAnUUID")))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testDeleteRevocationBatchFailedBatchNotFound() throws Exception {
        testSuccessfulUpload();

        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(new BatchDeleteRequestDto(UUID.randomUUID().toString())))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isNotFound());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testDeleteRevocationBatchFailedInvalidCountry() throws Exception {
        testSuccessfulUpload();

        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX");
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        BatchDeleteRequestDto deleteRequestDto = new BatchDeleteRequestDto(
            revocationBatchRepository.findAll().get(0).getBatchId()
        );

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, "XX");

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), "C=XX")
            )
            .andExpect(status().isForbidden());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testDeleteRevocationBatchFailedUploadDoesNotMatchAuth() throws Exception {
        testSuccessfulUpload();

        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX");
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        BatchDeleteRequestDto deleteRequestDto = new BatchDeleteRequestDto(
            revocationBatchRepository.findAll().get(0).getBatchId()
        );

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isForbidden());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testDeleteRevocationBatchFailedInvalidCmsSignature() throws Exception {
        testSuccessfulUpload();

        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        BatchDeleteRequestDto deleteRequestDto = new BatchDeleteRequestDto(
            revocationBatchRepository.findAll().get(0).getBatchId()
        );

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }


    private void assertEquals(BatchDto expected, BatchDto actual) {
        Assertions.assertEquals(expected.getKid(), actual.getKid());
        Assertions.assertEquals(expected.getExpires().toEpochSecond(), actual.getExpires().toEpochSecond());
        Assertions.assertEquals(expected.getHashType(), actual.getHashType());
        Assertions.assertEquals(expected.getCountry(), actual.getCountry());
        Assertions.assertEquals(expected.getEntries(), actual.getEntries());
    }
}
