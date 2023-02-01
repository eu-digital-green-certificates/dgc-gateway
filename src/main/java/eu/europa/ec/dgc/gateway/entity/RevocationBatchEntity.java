/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 - 2022 T-Systems International GmbH and all other contributors
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

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import java.time.ZonedDateTime;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "revocation_batch", indexes = @Index(columnList = "batchId"))
@AllArgsConstructor
@NoArgsConstructor
public class RevocationBatchEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    /**
     * ID of the Batch.
     */
    @Column(name = "batchId", nullable = false, length = 36, unique = true)
    private String batchId;

    /**
     * ISO 3166 Alpha-2 Country Code.
     * (plus code "EU" for administrative European Union entries).
     */
    @Column(name = "country", nullable = false, length = 2)
    private String country;

    /**
     * Timestamp of the Batch when it was added or deleted.
     */
    @Column(name = "changed", nullable = false)
    private ZonedDateTime changed = ZonedDateTime.now();

    /**
     * Timestamp when the Batch will expire.
     */
    @Column(name = "expires", nullable = false)
    private ZonedDateTime expires;

    /**
     * Flag that indicates whether this batch was already deleted.
     */
    @Column(name = "deleted", nullable = false)
    private Boolean deleted = false;

    /**
     * Type of Revocation Hashes.
     */
    @Column(name = "type", nullable = false)
    @Enumerated(EnumType.STRING)
    private RevocationHashType type;

    /**
     * The KID of the Key used to sign the CMS.
     */
    @Column(name = "kid", length = 12)
    private String kid;

    /**
     * The Signed CMS with the batch.
     */
    @Column(name = "signed_batch", length = 1_024_000)
    @Lob
    private String signedBatch;

    /**
     * Available types of Hash.
     */
    public enum RevocationHashType {
        SIGNATURE,
        UCI,
        COUNTRYCODEUCI
    }

}
