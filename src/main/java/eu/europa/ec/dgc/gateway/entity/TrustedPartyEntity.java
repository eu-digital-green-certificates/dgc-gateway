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

package eu.europa.ec.dgc.gateway.entity;

import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Fetch;
import org.hibernate.annotations.FetchMode;

@Getter
@Setter
@Entity
@Table(name = "trusted_party")
public class TrustedPartyEntity extends FederatedEntity {

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
     * KID of the certificate (Optional, use to override default KID -> first 8 bytes of SHA-256 thumbprint).
     */
    @Column(name = "kid", length = 20, unique = true)
    private String kid;

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
    @Column(name = "certificate_type", nullable = false, length = 25)
    @Enumerated(EnumType.STRING)
    CertificateType certificateType;

    @Enumerated(EnumType.STRING)
    @ElementCollection(fetch = FetchType.EAGER)
    @Fetch(FetchMode.SUBSELECT)
    @CollectionTable(name = "trusted_party_roles")
    @Column(name = "role", length = 22, nullable = false)
    List<CertificateRoles> certificateRoles;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assigned_gateway", referencedColumnName = "gateway_id")
    FederationGatewayEntity assignedGateway;

    public enum CertificateType {
        /**
         * Certificate which the member state is using to authenticate at DGC Gateway (NBTLS).
         */
        AUTHENTICATION,

        /**
         * Certificate to verify identity of Federation Gateway.
         */
        AUTHENTICATION_FEDERATION,

        /**
         * Certificate which the member state is using to sign the uploaded information (NBUS).
         */
        UPLOAD,

        /**
         * Country Signing Certificate Authority certificate (NBCSCA).
         */
        CSCA,

        /**
         * Certificate used to offline sign entries in database (NBTA).
         */
        TRUSTANCHOR;

        /**
         * Return a List of allowed CertificateType as String List.
         */
        public static List<String> stringValues() {
            return Arrays.stream(TrustedPartyEntity.CertificateType.values())
                .map(Enum::toString)
                .collect(Collectors.toList());
        }
    }

    public enum CertificateRoles {
        /**
         * User with this certificate is allowed to download Revocation List.
         */
        REVOCATION_LIST_READER,

        /**
         * User with this certificate is allowed to upload Revocation List.
         */
        REVOCATION_UPLOADER,

        /**
         * User with this certificate is allowed to delete Revocation List.
         */
        REVOCATION_DELETER
    }
}
