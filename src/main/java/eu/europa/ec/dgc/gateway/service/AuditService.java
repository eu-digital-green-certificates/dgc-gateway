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
import eu.europa.ec.dgc.gateway.repository.AuditEventRepository;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.utils.CertificateUtils;
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

    private static final String MDC_PROP_AUDIT_ID = "auditId";
    private static final String MDC_PROP_AUDIT_COUNTRY = "country";

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
        auditEventEntity.setAuthenticationSha256Fingerprint(authenticationSha256Fingerprint);
        auditEventEntity.setUploaderSha256Fingerprint(uploaderSha256Fingerprint);
        log.debug("Created AuditEvent with ID {} for Country {} with uploader {} authentication{}", auditEvent,
            countryCode, uploaderSha256Fingerprint, authenticationSha256Fingerprint);
        DgcMdc.put(MDC_PROP_AUDIT_COUNTRY, countryCode);
        DgcMdc.put(MDC_PROP_AUDIT_ID, auditEvent);
        log.info("Created AuditEvent");
        auditEventRepository.save(auditEventEntity);
    }
}
