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
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
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
@Table(name = "signer_information")
@AllArgsConstructor
@NoArgsConstructor
public class SignerInformationEntity extends FederatedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    /**
     * Timestamp of the Record.
     */
    @Column(name = "created_at", nullable = false)
    private ZonedDateTime createdAt = ZonedDateTime.now();

    @Column(name = "deleted_at")
    private ZonedDateTime deletedAt;

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
     * Signature of the Upload Certificate.
     */
    @Column(name = "signature", length = 6000)
    String signature;

    /**
     * KID of the certificate (Optional, use to override default KID -> first 8 bytes of SHA-256 thumbprint).
     */
    @Column(name = "kid", length = 20, unique = true)
    private String kid;

    /**
     * Type of the certificate (currently only DSC).
     */
    @Column(name = "certificate_type", nullable = false)
    @Enumerated(EnumType.STRING)
    CertificateType certificateType;


    @Column(name = "properties", length = 2000)
    private String properties;

    public enum CertificateType {

        /**
         * Certificate which the member state is using to sign documents (NBDSC).
         */
        DSC,

        SIGN,

        AUTH,

        CUSTOM;

        /**
         * Return a List of allowed CertificateType as String List.
         */
        public static List<String> stringValues() {
            return Arrays.stream(CertificateType.values())
                .map(Enum::toString)
                .collect(Collectors.toList());
        }
    }

}
