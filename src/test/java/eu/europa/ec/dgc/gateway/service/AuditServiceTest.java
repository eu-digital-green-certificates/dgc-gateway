package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.repository.AuditEventRepositorty;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class AuditServiceTest {
    @Autowired
    AuditService auditService;
    @Autowired
    AuditEventRepositorty auditEventRepositorty;

    private static final String countryCode = "EU";
    private static final String dummySignature = "randomStringAsSignatureWhichIsNotValidatedInServiceLevel";

    @Test
    public void testSuccessfulCreateAuditEvent() throws Exception {
        long count = auditEventRepositorty.count() + 1;

        auditService.addAuditEvent(countryCode,dummySignature,
                dummySignature, "postVerificationInformation_ALREADY_EXIST_CHECK_FAILED", "ALREADY_EXIST_CHECK_FAILED");

        Assertions.assertEquals(count, auditEventRepositorty.count());
    }
}
