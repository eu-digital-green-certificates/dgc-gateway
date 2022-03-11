/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway
 * ---
 * Copyright (C) 2022 T-Systems International GmbH and all other contributors
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

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedReferenceEntity;
import eu.europa.ec.dgc.gateway.repository.FederationGatewayRepository;
import eu.europa.ec.dgc.gateway.repository.TrustedReferenceRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDto;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwTrustedReferenceMapper;
import eu.europa.ec.dgc.gateway.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.time.ZonedDateTime;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class TrustedReferenceServiceTest {

    @Autowired
    TrustedReferenceRepository trustedReferenceRepository;

    @Autowired
    TrustedReferenceService trustedReferenceService;

    @Autowired
    FederationGatewayRepository federationGatewayRepository;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    DgcTestKeyStore dgcTestKeyStore;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    GwTrustedReferenceMapper trustedReferenceMapper;

    private static final String countryCode = "EU";
    private static final String countryCode2 = "DE";

    private TrustedReferenceEntity testEntity, federatedTestEntity;
    private FederationGatewayEntity federationGatewayEntity;

    @BeforeEach
    void testData() {
        trustedReferenceRepository.deleteAll();
        federationGatewayRepository.deleteAll();

        federationGatewayEntity = federationGatewayRepository.save(new FederationGatewayEntity(null, ZonedDateTime.now(),
            "gw-id", "endpoint", "kid", "pk", "impl",
            FederationGatewayEntity.DownloadTarget.FEDERATION, FederationGatewayEntity.Mode.APPEND, "sig",
            -1L, null, null, 0L, null, null));

        testEntity = trustedReferenceRepository.save(new TrustedReferenceEntity(null,
            ZonedDateTime.now(), "http://example.org", countryCode2, TrustedReferenceEntity.ReferenceType.DCC,
            "service", "thumbprint", "name", "pk", "contentType",
            TrustedReferenceEntity.SignatureType.CMS, "version"));

        federatedTestEntity = new TrustedReferenceEntity(null,
            ZonedDateTime.now(), "http://example.org", countryCode, TrustedReferenceEntity.ReferenceType.FHIR,
            "service", "thumbprint", "name", "pk", "contentType",
            TrustedReferenceEntity.SignatureType.JWS, "version");
        federatedTestEntity.setSourceGateway(federationGatewayEntity);
        federatedTestEntity = trustedReferenceRepository.save(federatedTestEntity);

        Assertions.assertEquals(2, trustedReferenceRepository.count());
    }

    @AfterEach
    void cleanUp() {
        trustedReferenceRepository.deleteAll();
    }

    @Test
    void testDelete() {
        trustedReferenceService.deleteBySourceGateway(federationGatewayEntity.getGatewayId());
        Assertions.assertEquals(1, trustedReferenceRepository.count());
    }

    @Test
    void testGetAll() {
        List<TrustedReferenceEntity> response = trustedReferenceService.getAllReferences();

        Assertions.assertEquals(2, response.size());
        assertEquals(testEntity, response.get(0));
        assertEquals(federatedTestEntity, response.get(1));
    }

    @Test
    void testGetByUuid() throws TrustedReferenceService.TrustedReferenceServiceException {
        TrustedReferenceEntity response = trustedReferenceService.getReference(testEntity.getUuid());
        assertEquals(testEntity, response);

        TrustedReferenceService.TrustedReferenceServiceException e = Assertions.assertThrows(TrustedReferenceService.TrustedReferenceServiceException.class, () -> {
            trustedReferenceService.getReference("randomNonExistentUuid");
        });

        Assertions.assertEquals(TrustedReferenceService.TrustedReferenceServiceException.Reason.NOT_FOUND, e.getReason());
    }

    @Test
    void testAddFederatedTrustedReference() {
        TrustedReferenceEntity anotherFederatedTestEntity = new TrustedReferenceEntity(null,
            ZonedDateTime.now(), "http://example.org", countryCode, TrustedReferenceEntity.ReferenceType.DCC,
            "service", "thumbprint", "name", "pk", "contentType",
            TrustedReferenceEntity.SignatureType.CMS, "version");
        anotherFederatedTestEntity.setSourceGateway(federationGatewayEntity);

        TrustedReferenceEntity returnedEntity = trustedReferenceService.addFederatedTrustedReference(
            anotherFederatedTestEntity.getCountry(),
            anotherFederatedTestEntity.getType(),
            anotherFederatedTestEntity.getUrl(),
            anotherFederatedTestEntity.getService(),
            anotherFederatedTestEntity.getName(),
            anotherFederatedTestEntity.getSignatureType(),
            anotherFederatedTestEntity.getThumbprint(),
            anotherFederatedTestEntity.getSslPublicKey(),
            anotherFederatedTestEntity.getReferenceVersion(),
            anotherFederatedTestEntity.getContentType(),
            anotherFederatedTestEntity.getDomain(),
            anotherFederatedTestEntity.getUuid(),
            anotherFederatedTestEntity.getSourceGateway()
        );

        assertEquals(anotherFederatedTestEntity, returnedEntity);

        TrustedReferenceEntity persistedEntity = trustedReferenceRepository.getByUuid(anotherFederatedTestEntity.getUuid()).orElseThrow();

        assertEquals(anotherFederatedTestEntity, persistedEntity);
    }

    @Test
    void testSearch() {
        // Search for federated entity
        List<TrustedReferenceEntity> response =
            trustedReferenceService.search(List.of(countryCode), List.of("DCC"), List.of("FHIR"), List.of("JWS"), true);
        Assertions.assertEquals(1, response.size());
        assertEquals(federatedTestEntity, response.get(0));

        // Search for federated entity but disable withFederation flag
        response = trustedReferenceService.search(List.of(countryCode), List.of("DCC"), List.of("FHIR"), List.of("JWS"), false);
        Assertions.assertTrue(response.isEmpty());

        // Search without country code
        response = trustedReferenceService.search(null, List.of("DCC"), List.of("FHIR"), List.of("JWS"), true);
        Assertions.assertEquals(1, response.size());
        assertEquals(federatedTestEntity, response.get(0));

        // Search without domain
        response = trustedReferenceService.search(List.of(countryCode), null, List.of("FHIR"), List.of("JWS"), true);
        Assertions.assertEquals(1, response.size());
        assertEquals(federatedTestEntity, response.get(0));

        // Search without type
        response = trustedReferenceService.search(List.of(countryCode), List.of("DCC"), null, List.of("JWS"), true);
        Assertions.assertEquals(1, response.size());
        assertEquals(federatedTestEntity, response.get(0));

        // Search without signature type
        response = trustedReferenceService.search(List.of(countryCode), List.of("DCC"), List.of("FHIR"), null, true);
        Assertions.assertEquals(1, response.size());
        assertEquals(federatedTestEntity, response.get(0));

    }

    @Test
    void testAddTrustedReference() throws Exception {
        TrustedReferenceDto dto = new TrustedReferenceDto(
            null,
            "https://example.org",
            1L,
            countryCode,
            TrustedReferenceDto.ReferenceTypeDto.DCC,
            "service",
            "thumbprint",
            "name",
            "pk",
            "contentType",
            TrustedReferenceDto.SignatureTypeDto.JWS,
            "refVersion"
        );

        TrustedReferenceEntity createdEntity = trustedReferenceService.addTrustedReference(
            objectMapper.writeValueAsString(dto),
            certificateUtils.convertCertificate(trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode)),
            countryCode
        );

        Assertions.assertNotNull(createdEntity);
        TrustedReferenceEntity entityinDb = trustedReferenceRepository.getByUuid(createdEntity.getUuid()).orElseThrow();
        assertEquals(trustedReferenceMapper.map(dto), entityinDb);
    }

    @Test
    void testAddTrustedReferenceInvalidJson() {
        TrustedReferenceService.TrustedReferenceServiceException e = Assertions.assertThrows(
            TrustedReferenceService.TrustedReferenceServiceException.class, () -> trustedReferenceService.addTrustedReference(
                "randomNonJsonString",
                certificateUtils.convertCertificate(trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode)),
                countryCode
            ));

        Assertions.assertEquals(TrustedReferenceService.TrustedReferenceServiceException.Reason.INVALID_JSON, e.getReason());
    }

    @Test
    void testAddTrustedReferenceInvalidJsonValues() {
        TrustedReferenceDto dto = new TrustedReferenceDto(
            null,
            "a".repeat(101), // too long
            1L,
            countryCode,
            TrustedReferenceDto.ReferenceTypeDto.DCC,
            "service",
            "thumbprint",
            "name",
            "pk",
            "contentType",
            TrustedReferenceDto.SignatureTypeDto.JWS,
            "refVersion"
        );

        TrustedReferenceService.TrustedReferenceServiceException e = Assertions.assertThrows(
            TrustedReferenceService.TrustedReferenceServiceException.class, () -> trustedReferenceService.addTrustedReference(
                objectMapper.writeValueAsString(dto),
                certificateUtils.convertCertificate(trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode)),
                countryCode
            ));

        Assertions.assertEquals(TrustedReferenceService.TrustedReferenceServiceException.Reason.INVALID_JSON_VALUES, e.getReason());
    }

    @Test
    void testAddTrustedReferenceInvalidUploadCertificate() {
        TrustedReferenceDto dto = new TrustedReferenceDto(
            null,
            "a",
            1L,
            countryCode,
            TrustedReferenceDto.ReferenceTypeDto.DCC,
            "service",
            "thumbprint",
            "name",
            "pk",
            "contentType",
            TrustedReferenceDto.SignatureTypeDto.JWS,
            "refVersion"
        );

        TrustedReferenceService.TrustedReferenceServiceException e = Assertions.assertThrows(
            TrustedReferenceService.TrustedReferenceServiceException.class, () -> trustedReferenceService.addTrustedReference(
                objectMapper.writeValueAsString(dto),
                certificateUtils.convertCertificate(trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode2)),
                countryCode
            ));

        Assertions.assertEquals(TrustedReferenceService.TrustedReferenceServiceException.Reason.UPLOADER_CERT_CHECK_FAILED, e.getReason());
    }

    @Test
    void testAddTrustedReferenceInvalidCountry() {
        TrustedReferenceDto dto = new TrustedReferenceDto(
            null,
            "a",
            1L,
            countryCode,
            TrustedReferenceDto.ReferenceTypeDto.DCC,
            "service",
            "thumbprint",
            "name",
            "pk",
            "contentType",
            TrustedReferenceDto.SignatureTypeDto.JWS,
            "refVersion"
        );

        TrustedReferenceService.TrustedReferenceServiceException e = Assertions.assertThrows(
            TrustedReferenceService.TrustedReferenceServiceException.class, () -> trustedReferenceService.addTrustedReference(
                objectMapper.writeValueAsString(dto),
                certificateUtils.convertCertificate(trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode)),
                countryCode2
            ));

        Assertions.assertEquals(TrustedReferenceService.TrustedReferenceServiceException.Reason.UPLOADER_CERT_CHECK_FAILED, e.getReason());
    }


    void assertEquals(TrustedReferenceEntity expected, TrustedReferenceEntity actual) {
        Assertions.assertEquals(expected.getService(), actual.getService());
        Assertions.assertEquals(expected.getCountry(), actual.getCountry());
        Assertions.assertEquals(expected.getReferenceVersion(), actual.getReferenceVersion());

        if (expected.getId() != null) {
            // Entity wasn't persisted, so skip this check
            Assertions.assertEquals(expected.getId(), actual.getId());
        }
        Assertions.assertEquals(expected.getName(), actual.getName());
        Assertions.assertEquals(expected.getThumbprint(), actual.getThumbprint());
        Assertions.assertEquals(expected.getContentType(), actual.getContentType());
        Assertions.assertEquals(expected.getSslPublicKey(), actual.getSslPublicKey());
        Assertions.assertEquals(expected.getUrl(), actual.getUrl());
    }

}
