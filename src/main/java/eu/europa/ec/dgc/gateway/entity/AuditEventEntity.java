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

package eu.europa.ec.dgc.gateway.entity;

import java.time.ZonedDateTime;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "audit_event")
@AllArgsConstructor
@NoArgsConstructor
public class AuditEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    /**
     * Timestamp of the Record.
     */
    @Column(name = "timestamp", nullable = false)
    private ZonedDateTime createdAt = ZonedDateTime.now();

    /**
     * ISO 3166 Alpha-2 Country Code.
     * (plus code "EU" for administrative European Union entries).
     */
    @Column(name = "country", nullable = false, length = 2)
    private String country;

    /**
     * uploader_sha256_fingerprint SHA256-fingerprint of the certificate.
     */
    @Column(name = "uploader_sha256_fingerprint", nullable = false, length = 64)
    private String uploaderSha256Fingerprint;

    /**
     * uploader_sha256_fingerprint SHA256-fingerprint of the certificate.
     */
    @Column(name = "authentication_sha256_fingerprint", nullable = false, length = 64)
    private String authenticationSha256Fingerprint;

    /**
     * ID of the event that was recorded.
     */
    @Column(name = "event", nullable = false, length = 64)
    private String event;

    /**
     * Description of the recorded event.
     */
    @Column(name = "description", nullable = false, length = 64)
    private String description;

}
