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
@Table(name = "trusted_reference")
public class TrustedReferenceEntity extends FederatedEntity {

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
     * Type of the reference (DSC, FHIR).
     */
    @Column(name = "reference_type", nullable = false, length = 25)
    @Enumerated(EnumType.STRING)
    private ReferenceType type;

    /**
     * Name of the Service, e.g. ValueSet, PlanDefinition
     */
    @Column(name = "service", nullable = false, length = 1024)
    private String service;

    /**
     * SHA-256 Thumbprint of the certificate (hex encoded).
     */
    @Column(name = "thumbprint", length = 64)
    private String thumbprint;

    /**
     * Name of the service.
     */
    @Column(name = "name", nullable = false, length = 512)
    private String name;

    /**
     * SSL Certificate of the endpoint (if applicable).
     */
    @Column(name = "ssl_public_key", length = 2048)
    private String sslPublicKey;

    /**
     * MIME type of content.
     */
    @Column(name = "content_type", nullable = false, length = 512)
    private String contentType;

    /**
     * Type of the signature (NONE, CMS, JWS).
     */
    @Column(name = "signature_type", nullable = false, length = 25)
    @Enumerated(EnumType.STRING)
    private SignatureType signatureType;

    public enum ReferenceType {
        DCC,
        FHIR
    }

    public enum SignatureType {
        CMS,
        JWS,
        NONE
    }
}
