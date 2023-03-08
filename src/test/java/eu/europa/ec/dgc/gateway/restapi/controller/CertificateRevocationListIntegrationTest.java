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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.ser.ZonedDateTimeSerializer;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.RevocationBatchEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.AuditEventRepository;
import eu.europa.ec.dgc.gateway.repository.RevocationBatchRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationBatchDeleteRequestDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationBatchDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationBatchListDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationHashTypeDto;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.signing.SignedMessageParser;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.signing.SignedStringMessageParser;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatterBuilder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@Slf4j
public class CertificateRevocationListIntegrationTest {

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

    @AfterEach
    public void teardown() throws Exception {
        trustedPartyTestHelper.setRoles(countryCode);
    }

    @Test
    void testSuccessfulUpload() throws Exception {
        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDto revocationBatchDto = new RevocationBatchDto();
        revocationBatchDto.setCountry(countryCode);
        revocationBatchDto.setExpires(ZonedDateTime.now().plusDays(7));
        revocationBatchDto.setHashType(RevocationHashTypeDto.SIGNATURE);
        revocationBatchDto.setKid("UNKNOWN_KID");
        revocationBatchDto.setEntries(List.of(
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe}))
        ));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(revocationBatchDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_UPLOADER);

        MvcResult mvcResult = mockMvc.perform(post("/revocation-list")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        ).andReturn();

        Assertions.assertEquals(HttpStatus.CREATED.value(), mvcResult.getResponse().getStatus());

        Assertions.assertEquals(revocationBatchesInDb + 1, revocationBatchRepository.count());
        Optional<RevocationBatchEntity> createdRevocationBatch =
            revocationBatchRepository.findAll().stream().findFirst();

        Assertions.assertTrue(createdRevocationBatch.isPresent());

        Assertions.assertEquals(auditEventEntitiesInDb + 1, auditEventRepository.count());
        Assertions.assertEquals(revocationBatchDto.getExpires().toEpochSecond(),
            createdRevocationBatch.get().getExpires().toEpochSecond());
        Assertions.assertTrue(
            ZonedDateTime.now().toEpochSecond() - 2 < createdRevocationBatch.get().getChanged().toEpochSecond()
                && ZonedDateTime.now().toEpochSecond() + 2 > createdRevocationBatch.get().getChanged().toEpochSecond());
        Assertions.assertEquals(countryCode, createdRevocationBatch.get().getCountry());
        Assertions.assertEquals(revocationBatchDto.getHashType().name(), createdRevocationBatch.get().getType().name());
        Assertions.assertEquals(revocationBatchDto.getKid(), createdRevocationBatch.get().getKid());
        Assertions.assertEquals(createdRevocationBatch.get().getBatchId(),
            mvcResult.getResponse().getHeader(HttpHeaders.ETAG));
        Assertions.assertEquals(36, createdRevocationBatch.get().getBatchId().length());

        SignedStringMessageParser parser = new SignedStringMessageParser(createdRevocationBatch.get().getSignedBatch());
        RevocationBatchDto parsedRevocationBatch =
            objectMapper.readValue(parser.getPayload(), RevocationBatchDto.class);

        assertEquals(revocationBatchDto, parsedRevocationBatch);
    }

    @Test
    void testUploadFailedInvalidJson() throws Exception {
        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload("randomBadString")
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_UPLOADER);

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

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDto revocationBatchDto = new RevocationBatchDto();
        revocationBatchDto.setCountry(countryCode);
        revocationBatchDto.setExpires(ZonedDateTime.now().plusDays(7));
        revocationBatchDto.setHashType(RevocationHashTypeDto.SIGNATURE);
        revocationBatchDto.setKid("KIDWHICHISWAYTOLONGTOPASS");
        revocationBatchDto.setEntries(List.of(
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe}))
        ));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(revocationBatchDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_UPLOADER);

        mockMvc.perform(post("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest())
            .andExpect(header().doesNotExist(HttpHeaders.ETAG));

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "ccccccccccccccccccccccccA",
        "__thisIsNoValidBase64___",
        "CgoKCgoKCgoKCgoKCgoKCgo=" // this base64 string is too long (17 bytes)
    })
    void testUploadFailedInvalidJsonValuesInHashEntries(String invalidHash) throws Exception {
        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDto revocationBatchDto = new RevocationBatchDto();
        revocationBatchDto.setCountry(countryCode);
        revocationBatchDto.setExpires(ZonedDateTime.now().plusDays(7));
        revocationBatchDto.setHashType(RevocationHashTypeDto.SIGNATURE);
        revocationBatchDto.setKid("UNKNOWN_KID");
        revocationBatchDto.setEntries(List.of(
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb})),
            new RevocationBatchDto.BatchEntryDto(invalidHash),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd}))
        ));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(revocationBatchDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_UPLOADER);

        mockMvc.perform(post("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest())
            .andExpect(header().doesNotExist(HttpHeaders.ETAG));

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testUploadFailedInvalidCountry() throws Exception {
        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDto revocationBatchDto = new RevocationBatchDto();
        revocationBatchDto.setCountry("XX");
        revocationBatchDto.setExpires(ZonedDateTime.now().plusDays(7));
        revocationBatchDto.setHashType(RevocationHashTypeDto.SIGNATURE);
        revocationBatchDto.setKid("UNKNOWN_KID");
        revocationBatchDto.setEntries(List.of(
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe}))
        ));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(revocationBatchDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_UPLOADER);

        mockMvc.perform(post("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isForbidden())
            .andExpect(header().doesNotExist(HttpHeaders.ETAG));

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testUploadFailedInvalidExpirationDate() throws Exception {
        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDto revocationBatchDto = new RevocationBatchDto();
        revocationBatchDto.setCountry(countryCode);
        revocationBatchDto.setExpires(ZonedDateTime.now().minusSeconds(10));
        revocationBatchDto.setHashType(RevocationHashTypeDto.SIGNATURE);
        revocationBatchDto.setKid("UNKNOWN_KID");
        revocationBatchDto.setEntries(List.of(
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd, 0xd})),
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe}))
        ));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(revocationBatchDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_UPLOADER);

        mockMvc.perform(post("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest())
            .andExpect(header().doesNotExist(HttpHeaders.ETAG));

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());
    }

    @Test
    void testDeleteRevocationBatch() throws Exception {
        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(false);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch("Batch1234");
        entity.setExpires(ZonedDateTime.now().plusDays(5));
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);


        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDeleteRequestDto deleteRequestDto = new RevocationBatchDeleteRequestDto(entity.getBatchId());

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isNoContent());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb + 1, auditEventRepository.count());

        RevocationBatchEntity deletedBatch = revocationBatchRepository.findAll().get(0);
        Assertions.assertNull(deletedBatch.getSignedBatch());
        Assertions.assertTrue(deletedBatch.getDeleted());
        Assertions.assertTrue(
            deletedBatch.getChanged().toEpochSecond() > ZonedDateTime.now().minusSeconds(2).toEpochSecond());
        Assertions.assertTrue(
            deletedBatch.getChanged().toEpochSecond() < ZonedDateTime.now().plusSeconds(2).toEpochSecond());
    }


    @Test
    void testDeleteRevocationBatchAlternativeEndpoint() throws Exception {
        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(false);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch("Batch1234");
        entity.setExpires(ZonedDateTime.now().plusDays(5));
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);


        long revocationBatchesInDb = revocationBatchRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDeleteRequestDto deleteRequestDto = new RevocationBatchDeleteRequestDto(entity.getBatchId());

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER);

        mockMvc.perform(post("/revocation-list/delete")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isNoContent());

        Assertions.assertEquals(revocationBatchesInDb, revocationBatchRepository.count());
        Assertions.assertEquals(auditEventEntitiesInDb + 1, auditEventRepository.count());

        RevocationBatchEntity deletedBatch = revocationBatchRepository.findAll().get(0);
        Assertions.assertNull(deletedBatch.getSignedBatch());
        Assertions.assertTrue(deletedBatch.getDeleted());
        Assertions.assertTrue(
            deletedBatch.getChanged().toEpochSecond() > ZonedDateTime.now().minusSeconds(2).toEpochSecond());
        Assertions.assertTrue(
            deletedBatch.getChanged().toEpochSecond() < ZonedDateTime.now().plusSeconds(2).toEpochSecond());
    }

    @Test
    void testDeleteRevocationBatchFailedInvalidJson() throws Exception {
        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(false);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch("Batch1234");
        entity.setExpires(ZonedDateTime.now().plusDays(5));
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);

        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload("randomString")
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());

        RevocationBatchEntity entityAfterDelete = revocationBatchRepository.findById(entity.getId()).orElseThrow();
        assertEquals(entity, entityAfterDelete);
    }

    @Test
    void testDeleteRevocationBatchFailedInvalidJsonValue() throws Exception {
        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(false);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch("Batch1234");
        entity.setExpires(ZonedDateTime.now().plusDays(5));
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);

        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(new RevocationBatchDeleteRequestDto("ThisIsNotAnUUID")))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());

        RevocationBatchEntity entityAfterDelete = revocationBatchRepository.findById(entity.getId()).orElseThrow();
        assertEquals(entity, entityAfterDelete);
    }

    @Test
    void testDeleteRevocationBatchFailedBatchNotFound() throws Exception {
        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(false);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch("Batch1234");
        entity.setExpires(ZonedDateTime.now().plusDays(5));
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);

        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(
                objectMapper.writeValueAsString(new RevocationBatchDeleteRequestDto(UUID.randomUUID().toString())))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isNotFound());

        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());

        RevocationBatchEntity entityAfterDelete = revocationBatchRepository.findById(entity.getId()).orElseThrow();
        assertEquals(entity, entityAfterDelete);
    }

    @Test
    void testDeleteRevocationBatchFailedInvalidCountry() throws Exception {
        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(false);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch("Batch1234");
        entity.setExpires(ZonedDateTime.now().plusDays(5));
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);

        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX");
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        RevocationBatchDeleteRequestDto deleteRequestDto = new RevocationBatchDeleteRequestDto(entity.getBatchId());

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, "XX");
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), "C=XX")
            )
            .andExpect(status().isForbidden());

        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());

        RevocationBatchEntity entityAfterDelete = revocationBatchRepository.findById(entity.getId()).orElseThrow();
        assertEquals(entity, entityAfterDelete);
    }

    @Test
    void testDeleteRevocationBatchFailedUploadDoesNotMatchAuth() throws Exception {
        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(false);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch("Batch1234");
        entity.setExpires(ZonedDateTime.now().plusDays(5));
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);

        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX");
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        RevocationBatchDeleteRequestDto deleteRequestDto = new RevocationBatchDeleteRequestDto(entity.getBatchId());

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isForbidden());

        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());

        RevocationBatchEntity entityAfterDelete = revocationBatchRepository.findById(entity.getId()).orElseThrow();
        assertEquals(entity, entityAfterDelete);
    }

    @Test
    void testDeleteRevocationBatchFailedInvalidCmsSignature() throws Exception {
        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(false);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch("Batch1234");
        entity.setExpires(ZonedDateTime.now().plusDays(5));
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);

        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        RevocationBatchDeleteRequestDto deleteRequestDto = new RevocationBatchDeleteRequestDto(entity.getBatchId());

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());

        RevocationBatchEntity entityAfterDelete = revocationBatchRepository.findById(entity.getId()).orElseThrow();
        assertEquals(entity, entityAfterDelete);
    }

    @Test
    void testDeleteRevocationBatchFailedGone() throws Exception {
        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(true);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch("Batch1234");
        entity.setExpires(ZonedDateTime.now().plusDays(5));
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);

        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDeleteRequestDto deleteRequestDto = new RevocationBatchDeleteRequestDto(entity.getBatchId());

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isGone());

        Assertions.assertEquals(auditEventEntitiesInDb, auditEventRepository.count());

        RevocationBatchEntity entityAfterDelete = revocationBatchRepository.findById(entity.getId()).orElseThrow();
        assertEquals(entity, entityAfterDelete);
    }

    @Test
    void testDownloadBatchList() throws Exception {

        ArrayList<RevocationBatchEntity> entities = new ArrayList<>();

        for (int i = 5500; i > 0; i--) {
            RevocationBatchEntity entity = new RevocationBatchEntity();
            entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
            entity.setBatchId(UUID.randomUUID().toString());
            entity.setDeleted(i % 2 == 0);
            entity.setKid("UNKNOWN_KID");
            entity.setSignedBatch("Batch1234");
            entity.setExpires(ZonedDateTime.now().plusDays(5));
            entity.setChanged(ZonedDateTime.now().minusMinutes(i));
            entity.setCountry(countryCode);
            entities.add(revocationBatchRepository.save(entity));
        }

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_LIST_READER);

        mockMvc.perform(get("/revocation-list")
                .accept("application/json")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                .header(HttpHeaders.IF_MODIFIED_SINCE,
                    entities.get(0).getChanged().minusSeconds(1).toOffsetDateTime().toString())
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.more").value(true))
            .andExpect(jsonPath("$.batches.length()").value(1000))
            .andDo(r -> evaluateDownloadedBatchList(r.getResponse(), entities.subList(0, 1000)));

        mockMvc.perform(get("/revocation-list")
                .accept("application/json")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                .header(HttpHeaders.IF_MODIFIED_SINCE,
                    entities.get(1000).getChanged().minusSeconds(1).toOffsetDateTime().toString())
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.more").value(true))
            .andExpect(jsonPath("$.batches.length()").value(1000))
            .andDo(r -> evaluateDownloadedBatchList(r.getResponse(), entities.subList(1000, 2000)));

        mockMvc.perform(get("/revocation-list")
                .accept("application/json")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                .header(HttpHeaders.IF_MODIFIED_SINCE,
                    entities.get(2000).getChanged().minusSeconds(1).toOffsetDateTime().toString())
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.more").value(true))
            .andExpect(jsonPath("$.batches.length()").value(1000))
            .andDo(r -> evaluateDownloadedBatchList(r.getResponse(), entities.subList(2000, 3000)));

        mockMvc.perform(get("/revocation-list")
                .accept("application/json")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                .header(HttpHeaders.IF_MODIFIED_SINCE,
                    entities.get(3000).getChanged().minusSeconds(1).toOffsetDateTime().toString())
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.more").value(true))
            .andExpect(jsonPath("$.batches.length()").value(1000))
            .andDo(r -> evaluateDownloadedBatchList(r.getResponse(), entities.subList(3000, 4000)));

        mockMvc.perform(get("/revocation-list")
                .accept("application/json")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                .header(HttpHeaders.IF_MODIFIED_SINCE,
                    entities.get(4000).getChanged().minusSeconds(1).toOffsetDateTime().toString())
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.more").value(true))
            .andExpect(jsonPath("$.batches.length()").value(1000))
            .andDo(r -> evaluateDownloadedBatchList(r.getResponse(), entities.subList(4000, 5000)));

        mockMvc.perform(get("/revocation-list")
                .accept("application/json")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                .header(HttpHeaders.IF_MODIFIED_SINCE,
                    entities.get(5000).getChanged().minusSeconds(1).toOffsetDateTime().toString())
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.more").value(false))
            .andExpect(jsonPath("$.batches.length()").value(500))
            .andDo(r -> evaluateDownloadedBatchList(r.getResponse(), entities.subList(5000, 5500)));

        mockMvc.perform(get("/revocation-list")
                .accept("application/json")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                .header(HttpHeaders.IF_MODIFIED_SINCE,
                    entities.get(5499).getChanged().plusSeconds(1).toOffsetDateTime().toString())
            )
            .andExpect(status().isNoContent());
    }

    @Test
    void testDownloadBatchListFailedNoIfModifiedSince() throws Exception {

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_LIST_READER);

        mockMvc.perform(get("/revocation-list")
                .accept("application/json")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());
    }

    @Test
    void testDownloadBatchListFailedIfModifiedSinceInFuture() throws Exception {

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_LIST_READER);

        mockMvc.perform(get("/revocation-list")
                .accept("application/json")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                .header(HttpHeaders.IF_MODIFIED_SINCE, OffsetDateTime.now().plusSeconds(1).toString())
            )
            .andExpect(status().isBadRequest());
    }

    @Test
    void testDownloadRevocationBatch() throws Exception {
        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDto batchDto = new RevocationBatchDto();
        batchDto.setCountry(countryCode);
        batchDto.setExpires(ZonedDateTime.now().plusDays(5));
        batchDto.setHashType(RevocationHashTypeDto.SIGNATURE);
        batchDto.setKid("UNKNOWN_KID");
        batchDto.setEntries(List.of(new RevocationBatchDto.BatchEntryDto("abcd")));

        String signedBatch = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(batchDto))
            .buildAsString();

        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(false);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch(signedBatch);
        entity.setExpires(batchDto.getExpires());
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_LIST_READER);

        mockMvc.perform(get("/revocation-list/" + entity.getBatchId())
                .accept("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andDo(result -> {
                SignedStringMessageParser parser =
                    new SignedStringMessageParser(result.getResponse().getContentAsString());

                Assertions.assertEquals(SignedMessageParser.ParserState.SUCCESS, parser.getParserState());
                Assertions.assertTrue(parser.isSignatureVerified());
                Assertions.assertArrayEquals(signerCertificate.getEncoded(),
                    parser.getSigningCertificate().getEncoded());

                RevocationBatchDto parsedBatch = objectMapper.readValue(parser.getPayload(), RevocationBatchDto.class);

                assertEquals(batchDto, parsedBatch);
            });
    }

    @Test
    void testDownloadRevocationBatchInvalidBatchId() throws Exception {
        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_LIST_READER);

        mockMvc.perform(get("/revocation-list/thisIsNotAnUUID")
                .accept("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());
    }

    @Test
    void testDownloadRevocationBatchGone() throws Exception {

        RevocationBatchEntity entity = new RevocationBatchEntity();
        entity.setType(RevocationBatchEntity.RevocationHashType.SIGNATURE);
        entity.setBatchId(UUID.randomUUID().toString());
        entity.setDeleted(true);
        entity.setKid("UNKNOWN_KID");
        entity.setSignedBatch("abcd");
        entity.setExpires(ZonedDateTime.now().plusDays(5));
        entity.setChanged(ZonedDateTime.now().minusDays(5));
        entity.setCountry(countryCode);
        revocationBatchRepository.save(entity);

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_LIST_READER);

        mockMvc.perform(get("/revocation-list/" + entity.getBatchId())
                .accept("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isGone());
    }

    @Test
    void testDownloadRevocationBatchNotFound() throws Exception {

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_LIST_READER);

        mockMvc.perform(get("/revocation-list/" + UUID.randomUUID())
                .accept("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isNotFound());
    }

    private void evaluateDownloadedBatchList(MockHttpServletResponse mockResponse,
                                             List<RevocationBatchEntity> expectedBatches)
        throws UnsupportedEncodingException, JsonProcessingException {
        RevocationBatchListDto revocationBatchListDto =
            objectMapper.readValue(mockResponse.getContentAsString(), RevocationBatchListDto.class);

        Assertions.assertEquals(expectedBatches.size(), revocationBatchListDto.getBatches().size());

        for (int i = 0; i < revocationBatchListDto.getBatches().size(); i++) {
            assertEquals(expectedBatches.get(i), revocationBatchListDto.getBatches().get(i));
        }
    }

    private static void assertEquals(RevocationBatchEntity expected,
                                     RevocationBatchListDto.RevocationBatchListItemDto actual) {
        Assertions.assertEquals(expected.getBatchId(), actual.getBatchId());
        Assertions.assertEquals(expected.getChanged().toEpochSecond(), actual.getDate().toEpochSecond());
        Assertions.assertEquals(expected.getCountry(), actual.getCountry());
        Assertions.assertEquals(expected.getDeleted(), actual.getDeleted());
    }


    private static void assertEquals(RevocationBatchDto expected, RevocationBatchDto actual) {
        Assertions.assertEquals(expected.getKid(), actual.getKid());
        Assertions.assertEquals(expected.getExpires().toEpochSecond(), actual.getExpires().toEpochSecond());
        Assertions.assertEquals(expected.getHashType(), actual.getHashType());
        Assertions.assertEquals(expected.getCountry(), actual.getCountry());
        Assertions.assertEquals(expected.getEntries(), actual.getEntries());
    }

    public static void assertEquals(RevocationBatchEntity expected, RevocationBatchEntity actual) {
        Assertions.assertEquals(expected.getBatchId(), actual.getBatchId());
        Assertions.assertEquals(expected.getCountry(), actual.getCountry());
        Assertions.assertEquals(expected.getKid(), actual.getKid());
        Assertions.assertEquals(expected.getType(), actual.getType());
        Assertions.assertEquals(expected.getExpires().toEpochSecond(), actual.getExpires().toEpochSecond());
        Assertions.assertEquals(expected.getChanged().toEpochSecond(), actual.getChanged().toEpochSecond());
        Assertions.assertEquals(expected.getDeleted(), actual.getDeleted());
        Assertions.assertEquals(expected.getId(), expected.getId());
        Assertions.assertEquals(expected.getSignedBatch(), expected.getSignedBatch());
    }

    @Test
    void testDownloadBatchListRequiresCorrectRole() throws Exception {

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER,
            TrustedPartyEntity.CertificateRoles.REVOCATION_UPLOADER);

        mockMvc.perform(get("/revocation-list")
                .accept("application/json")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                .header(HttpHeaders.IF_MODIFIED_SINCE, OffsetDateTime.now().toString())
            )
            .andExpect(status().isForbidden());
    }

    @Test
    void testDeleteRevocationBatchRequiresCorrectRole() throws Exception {
        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDeleteRequestDto deleteRequestDto =
            new RevocationBatchDeleteRequestDto(UUID.randomUUID().toString());

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_UPLOADER,
            TrustedPartyEntity.CertificateRoles.REVOCATION_LIST_READER);

        mockMvc.perform(delete("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isForbidden());

        mockMvc.perform(post("/revocation-list/delete")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isForbidden());
    }

    @Test
    void testUploadRequiresCorrectRole() throws Exception {
        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        RevocationBatchDto revocationBatchDto = new RevocationBatchDto();
        revocationBatchDto.setCountry(countryCode);
        revocationBatchDto.setExpires(ZonedDateTime.now().plusDays(7));
        revocationBatchDto.setHashType(RevocationHashTypeDto.SIGNATURE);
        revocationBatchDto.setKid("UNKNOWN_KID");
        revocationBatchDto.setEntries(List.of(
            new RevocationBatchDto.BatchEntryDto(Base64.getEncoder().encodeToString(
                new byte[] {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa}))));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(revocationBatchDto))
            .buildAsString();

        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_LIST_READER,
            TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER);

        mockMvc.perform(post("/revocation-list")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isForbidden())
            .andExpect(header().doesNotExist(HttpHeaders.ETAG));
    }

    @Test
    void testDownloadRevocationBatchRequiresCorrectRole() throws Exception {
        String authCertHash =
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedPartyTestHelper.setRoles(countryCode, TrustedPartyEntity.CertificateRoles.REVOCATION_DELETER,
            TrustedPartyEntity.CertificateRoles.REVOCATION_UPLOADER);

        mockMvc.perform(get("/revocation-list/" + UUID.randomUUID())
                .accept("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isForbidden());
    }
}
