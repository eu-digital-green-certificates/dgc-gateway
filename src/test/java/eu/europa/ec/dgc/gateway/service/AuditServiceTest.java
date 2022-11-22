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

import eu.europa.ec.dgc.gateway.entity.AuditEventEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.AuditEventRepository;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.utils.CertificateUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuditServiceTest {

    @Autowired
    AuditService auditService;

    @Autowired
    AuditEventRepository auditEventRepository;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    CertificateUtils certificateUtils;

    private static final String countryCode = "EU";
    private static final String dummySignature = "randomStringAsSignatureWhichIsNotValidatedInServiceLevel";

    @Test
    void testSuccessfulCreateAuditEvent() {
        auditEventRepository.deleteAll();
        String exampleEvent = "postVerificationInformation_ALREADY_EXIST_CHECK_FAILED";
        String exampleEventDescription = "ALREADY_EXIST_CHECK_FAILED";

        auditService.addAuditEvent(countryCode, dummySignature,
            dummySignature, exampleEvent, exampleEventDescription);

        Assertions.assertEquals(1, auditEventRepository.count());
        AuditEventEntity auditEvent = auditEventRepository.findAll().get(0);

        Assertions.assertEquals(countryCode, auditEvent.getCountry());
        Assertions.assertEquals(dummySignature, auditEvent.getAuthenticationSha256Fingerprint());
        Assertions.assertEquals(dummySignature, auditEvent.getUploaderSha256Fingerprint());
        Assertions.assertEquals(exampleEvent, auditEvent.getEvent());
        Assertions.assertEquals(exampleEventDescription, auditEvent.getDescription());
    }

    @Test
    void testSuccessfulCreateAuditEventWithCertificate() throws Exception {
        auditEventRepository.deleteAll();
        String exampleEvent = "postVerificationInformation_ALREADY_EXIST_CHECK_FAILED";
        String exampleEventDescription = "ALREADY_EXIST_CHECK_FAILED";

        auditService.addAuditEvent(
            countryCode,
            certificateUtils.convertCertificate(
                trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode)),
            dummySignature,
            exampleEvent,
            exampleEventDescription);

        Assertions.assertEquals(1, auditEventRepository.count());
        AuditEventEntity auditEvent = auditEventRepository.findAll().get(0);

        Assertions.assertEquals(countryCode, auditEvent.getCountry());
        Assertions.assertEquals(dummySignature, auditEvent.getAuthenticationSha256Fingerprint());
        Assertions.assertEquals(trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.UPLOAD, countryCode),
            auditEvent.getUploaderSha256Fingerprint());
        Assertions.assertEquals(exampleEvent, auditEvent.getEvent());
        Assertions.assertEquals(exampleEventDescription, auditEvent.getDescription());
    }
}
