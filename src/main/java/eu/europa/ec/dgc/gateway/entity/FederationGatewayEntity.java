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

import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "federation_gateway", indexes = {@Index(columnList = "gateway_id")})
@AllArgsConstructor
@NoArgsConstructor
public class FederationGatewayEntity implements Serializable {

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
     * Unique ID of the peer gateway.
     */
    @Column(name = "gateway_id", nullable = false, length = 36)
    private String gatewayId = UUID.randomUUID().toString();

    /**
     * URL of the peer gateway.
     */
    @Column(name = "gateway_endpoint", nullable = false, length = 200)
    private String gatewayEndpoint;

    /**
     * KID/Alias of the Client Certificate used to contact the peer gateway.
     */
    @Column(name = "gateway_kid", length = 50, nullable = false)
    private String gatewayKid;

    /**
     * Base64 encoded PublicKey of the peer gateway to validate signed packages.
     * (Reserved for future use)
     */
    @Column(name = "gateway_public_key", length = 200)
    private String gatewayPublicKey;

    /**
     * Implementation used to Download the Data.
     */
    @Column(name = "downloader_implementation", length = 50)
    private String downloaderImplementation;

    /**
     * tbd.
     */
    @Column(name = "download_target", length = 12, nullable = false)
    @Enumerated(EnumType.STRING)
    private DownloadTarget downloadTarget;

    /**
     * Operation mode of this peer Gateway.
     */
    @Column(name = "mode", length = 8, nullable = false)
    @Enumerated(EnumType.STRING)
    private Mode mode;

    /**
     * Signature of the TrustAnchor.
     * Calculated over Gateway ID, Gateway Endpoint, Gateway KID, Gateway Public Key,
     * Downloader Implementation, Download Target and Mode.
     */
    @Column(name = "signature", nullable = false, length = 6000)
    private String signature;

    /**
     * Interval between incremental downloads.
     * Set to NULL to disable federated gateway.
     */
    @Column(name = "download_interval")
    private Long downloadInterval;

    /**
     * Timestamp of last download.
     */
    @Column(name = "last_download")
    private ZonedDateTime lastDownload;

    /**
     * Count of retries since last successful download.
     */
    @Column(name = "retry_count")
    private Long retryCount;

    /**
     * Error Response/Reason in case of failed download.
     */
    @Column(name = "status_message", length = 500)
    private String statusMessage;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "assignedGateway")
    private List<TrustedPartyEntity> trustedParties;

    public enum DownloadTarget {
        FEDERATION,

        GATEWAY_ONLY
    }

    public enum Mode {
        APPEND,

        OVERRIDE
    }

}
