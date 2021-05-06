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
        Assertions.assertEquals(trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.UPLOAD, countryCode), auditEvent.getUploaderSha256Fingerprint());
        Assertions.assertEquals(exampleEvent, auditEvent.getEvent());
        Assertions.assertEquals(exampleEventDescription, auditEvent.getDescription());
    }
}
