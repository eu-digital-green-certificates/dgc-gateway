package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.entity.AuditEventEntity;
import eu.europa.ec.dgc.gateway.repository.AuditEventRepository;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.time.LocalDateTime;
import java.time.ZoneId;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuditService {

    private final AuditEventRepository auditEventRepository;

    private final CertificateUtils certificateUtils;

    /**
     * Method to create an audit Event.
     *
     * @param countryCode                     2-digit country Code
     * @param uploaderCertificate             the uploader cert
     * @param authenticationSha256Fingerprint fingerprint of the authentication cert
     * @param auditEvent                      Event ID
     * @param auditEventDescription           EventDescription
     */
    public void addAuditEvent(String countryCode, X509CertificateHolder uploaderCertificate,
                              String authenticationSha256Fingerprint,
                              String auditEvent, String auditEventDescription) {
        addAuditEvent(
            countryCode,
            certificateUtils.getCertThumbprint(uploaderCertificate),
            authenticationSha256Fingerprint,
            auditEvent,
            auditEventDescription
        );
    }

    /**
     * Method to create an audit Event.
     *
     * @param countryCode                     2-digit country Code
     * @param uploaderSha256Fingerprint       fingerprint of the uploader cert
     * @param authenticationSha256Fingerprint fingerprint of the authentication cert
     * @param auditEvent                      Event ID
     * @param auditEventDescription           EventDescription
     */
    public void addAuditEvent(String countryCode, String uploaderSha256Fingerprint,
                              String authenticationSha256Fingerprint, String auditEvent, String auditEventDescription) {
        AuditEventEntity auditEventEntity = new AuditEventEntity();
        auditEventEntity.setEvent(auditEvent);
        auditEventEntity.setDescription(auditEventDescription);
        auditEventEntity.setCountry(countryCode);
        auditEventEntity.setCreatedAt(LocalDateTime.now().atZone(ZoneId.of("UTC")));
        auditEventEntity.setAuthenticationSha256Fingerprint(authenticationSha256Fingerprint);
        auditEventEntity.setUploaderSha256Fingerprint(uploaderSha256Fingerprint);
        log.debug("Created AuditEvent with ID {} for Country {} with uploader {} authentication{}", auditEvent,
            countryCode, uploaderSha256Fingerprint, authenticationSha256Fingerprint);
        log.info("Created AuditEvent with ID {} for Country {} ", auditEvent, countryCode);
        auditEventRepository.save(auditEventEntity);
    }
}
