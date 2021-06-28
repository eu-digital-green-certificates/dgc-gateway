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
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "trusted_party")
public class TrustedPartyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    /**
     * Timestamp of the Record.
     */
    @Column(name = "created_at", nullable = false)
    private ZonedDateTime createdAt = ZonedDateTime.now();

    /**
     * ISO 3166 Alpha-2 Country Code
     * (plus code "EU" for administrative European Union entries).
     */
    @Column(name = "country", nullable = false, length = 2)
    private String country;

    /**
     * SHA-256 Thumbprint of the certificate (hex encoded).
     */
    @Column(name = "thumbprint", nullable = false, length = 64, unique = true)
    private String thumbprint;

    /**
     * Base64 encoded certificate raw data.
     */
    @Column(name = "raw_data", nullable = false, length = 4096)
    String rawData;

    /**
     * Signature of the TrustAnchor.
     */
    @Column(name = "signature", nullable = false, length = 6000)
    String signature;

    /**
     * Type of the certificate (Authentication, Upload, CSCA).
     */
    @Column(name = "certificate_type", nullable = false)
    @Enumerated(EnumType.STRING)
    CertificateType certificateType;

    public enum CertificateType {
        /**
         * Certificate which the member state is using to authenticate at DGC Gateway (NBTLS).
         */
        AUTHENTICATION,

        /**
         * Certificate which the member state is using to sign the uploaded information (NBUS).
         */
        UPLOAD,

        /**
         * Country Signing Certificate Authority certificate (NBCSCA).
         */
        CSCA
    }
}
