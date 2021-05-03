package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.repository.AuditEventRepository;
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

    private static final String countryCode = "EU";
    private static final String dummySignature = "randomStringAsSignatureWhichIsNotValidatedInServiceLevel";

    @Test
    void testSuccessfulCreateAuditEvent() throws Exception {
        long count = auditEventRepository.count() + 1;

        auditService.addAuditEvent(countryCode,dummySignature,
                dummySignature, "postVerificationInformation_ALREADY_EXIST_CHECK_FAILED", "ALREADY_EXIST_CHECK_FAILED");

        Assertions.assertEquals(count, auditEventRepository.count());
    }
}
