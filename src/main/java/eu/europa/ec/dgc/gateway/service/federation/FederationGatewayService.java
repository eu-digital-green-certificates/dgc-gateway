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

package eu.europa.ec.dgc.gateway.service.federation;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.repository.FederationGatewayRepository;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.signing.SignedMessageParser;
import eu.europa.ec.dgc.signing.SignedStringMessageParser;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class FederationGatewayService {

    private static final String MDC_PROP_GATEWAY_ID = "gatewayId";
    private static final String MDC_PROP_PARSER_STATE = "parserState";
    private static final String hashSeperator = ";";
    private final FederationGatewayRepository federationGatewayRepository;
    private final KeyStore trustAnchorKeyStore;
    private final DgcConfigProperties dgcConfigProperties;
    private final CertificateUtils certificateUtils;

    /**
     * Method to query the db for all Federation Gateways with set Download Interval
     *
     * @return List holding the found Gateways.
     */
    public List<FederationGatewayEntity> getActiveFederationGateways() {

        return federationGatewayRepository.getByDownloadIntervalIsNotNull()
            .stream()
            .filter(this::validateEntityIntegrity)
            .collect(Collectors.toList());
    }

    /**
     * Method to query the db for a Federation Gateway.
     *
     * @param gatewayId Gateway ID of the requested Gateway
     * @return Optional holding the certificate if found.
     */
    public Optional<FederationGatewayEntity> getFederationGateway(String gatewayId) {

        return federationGatewayRepository.getByGatewayId(gatewayId)
            .map(entity -> validateEntityIntegrity(entity) ? entity : null);
    }

    private boolean validateEntityIntegrity(FederationGatewayEntity federationGatewayEntity) {

        DgcMdc.put(MDC_PROP_GATEWAY_ID, federationGatewayEntity.getGatewayId());

        // load DGCG Trust Anchor PublicKey from KeyStore
        X509CertificateHolder trustAnchor;
        try {
            trustAnchor = certificateUtils.convertCertificate((X509Certificate) trustAnchorKeyStore.getCertificate(
                dgcConfigProperties.getTrustAnchor().getCertificateAlias()));
        } catch (KeyStoreException | CertificateEncodingException | IOException e) {
            log.error("Could not load DGCG-TrustAnchor from KeyStore.", e);
            return false;
        }

        // verify signature
        SignedStringMessageParser parser = new SignedStringMessageParser(
            federationGatewayEntity.getSignature(),
            Base64.getEncoder().encodeToString(getHashData(federationGatewayEntity).getBytes(StandardCharsets.UTF_8)));

        if (parser.getParserState() != SignedMessageParser.ParserState.SUCCESS) {
            DgcMdc.put(MDC_PROP_PARSER_STATE, parser.getParserState().name());
            log.error("TrustAnchor Verification failed.");
            return false;
        }

        if (!parser.isSignatureVerified()) {
            log.error("TrustAnchor Verification failed: Signature is not matching signed gateway configuration");
            return false;
        }

        if (!parser.getSigningCertificate().equals(trustAnchor)) {
            log.error("TrustAnchor Verification failed: Gateway Configuration was not signed by known TrustAnchor");
            return false;
        }

        return true;
    }

    /**
     * Update Status for Federation Gateway.
     *
     * @param gateway The Gateway to set the status for
     * @param success Flag whether download was sucesfull or not
     * @param message optional status message with details or failure reason
     */
    public void setStatus(FederationGatewayEntity gateway, boolean success, String message) {
        if (success) {
            gateway.setLastSuccessfulDownload(ZonedDateTime.now());
            gateway.setRetryCount(0L);
        } else {
            gateway.setRetryCount(
                Objects.requireNonNullElse(gateway.getRetryCount(), 0L) + 1);
        }
        gateway.setStatusMessage(message);
        gateway.setLastDownload(ZonedDateTime.now());

        federationGatewayRepository.save(gateway);
    }

    private String getHashData(FederationGatewayEntity entity) {
        return entity.getGatewayId() + hashSeperator
            + entity.getGatewayEndpoint() + hashSeperator
            + entity.getGatewayKid() + hashSeperator
            + entity.getGatewayPublicKey() + hashSeperator
            + entity.getDownloaderImplementation() + hashSeperator
            + entity.getDownloadTarget() + hashSeperator
            + entity.getMode();
    }
}
