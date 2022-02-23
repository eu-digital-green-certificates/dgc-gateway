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

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedIssuerRepository;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TrustedIssuerService {

    private static final String MDC_PROP_ISSUER_UUID = "issuerUuid";
    private static final String MDC_PROP_PARSER_STATE = "parserState";
    private static final String HASH_SEPARATOR = ";";
    private final TrustedIssuerRepository trustedIssuerRepository;
    private final TrustedPartyService trustedPartyService;
    private final KeyStore trustAnchorKeyStore;
    private final DgcConfigProperties dgcConfigProperties;
    private final CertificateUtils certificateUtils;

    /**
     * Method to query the db for all trusted issuers.
     *
     * @return List holding the found trusted issuers.
     */
    public List<TrustedIssuerEntity> getAllIssuers() {
        return trustedIssuerRepository.findAll()
            .stream()
            .filter(this::validateTrustedIssuerIntegrity)
            .collect(Collectors.toList());
    }

    /**
     * Method to query the db for trusted issuers by countryCode.
     *
     * @return List holding the found trusted issuers.
     */
    public List<TrustedIssuerEntity> getAllIssuers(final String countryCode) {
        return trustedIssuerRepository.getAllByCountry(countryCode)
            .stream()
            .filter(this::validateTrustedIssuerIntegrity)
            .collect(Collectors.toList());
    }

    /**
     * Search for TrustedIssuers by given criteria.
     *
     * @param domain         List of possible values for domain
     * @param country        List of possible values for country
     * @param withFederation Flag whether to include federated data.
     * @return Matching Entities
     */
    public List<TrustedIssuerEntity> search(List<String> domain, List<String> country, boolean withFederation) {
        if (withFederation) {
            return trustedIssuerRepository.search(
                    country, country == null || country.isEmpty(),
                    domain, domain == null || domain.isEmpty())
                .stream()
                .filter(this::validateTrustedIssuerIntegrity)
                .collect(Collectors.toList());
        } else {
            return trustedIssuerRepository.searchNonFederated(
                    country, country == null || country.isEmpty(),
                    domain, domain == null || domain.isEmpty())
                .stream()
                .filter(this::validateTrustedIssuerIntegrity)
                .collect(Collectors.toList());
        }
    }

    private boolean validateTrustedIssuerIntegrity(TrustedIssuerEntity trustedIssuerEntity) {

        DgcMdc.put(MDC_PROP_ISSUER_UUID, trustedIssuerEntity.getUuid());

        if (StringUtils.isEmpty(trustedIssuerEntity.getSignature())) {
            log.error("Certificate entity does not contain raw certificate or certificate signature.");
            return false;
        }

        List<X509CertificateHolder> trustAnchors = new ArrayList<>();
        if (trustedIssuerEntity.getSourceGateway() == null) {
            log.debug("TrustedIssuer is not federated, using TrustAnchor from Keystore");
            try {
                trustAnchors.add(certificateUtils.convertCertificate(
                    (X509Certificate) trustAnchorKeyStore.getCertificate(
                        dgcConfigProperties.getTrustAnchor().getCertificateAlias())));
            } catch (KeyStoreException | CertificateEncodingException | IOException e) {
                log.error("Could not load DGCG-TrustAnchor from KeyStore.", e);
                return false;
            }
        } else {
            log.debug("TrustedIssuer is federated, fetching TrustAnchors from Database.");
            trustedIssuerEntity.getSourceGateway().getTrustedParties().stream()
                .filter(gatewayTrustedParty -> gatewayTrustedParty.getCertificateType()
                    == TrustedPartyEntity.CertificateType.TRUSTANCHOR)
                .filter(trustedPartyService::validateCertificateIntegrity)
                .map(trustedPartyService::getX509CertificateHolderFromEntity)
                .forEach(trustAnchors::add);
        }

        // verify signature
        SignedStringMessageParser parser = new SignedStringMessageParser(
            trustedIssuerEntity.getSignature(),
            Base64.getEncoder().encodeToString(getHashData(trustedIssuerEntity).getBytes(StandardCharsets.UTF_8)));

        if (parser.getParserState() != SignedMessageParser.ParserState.SUCCESS) {
            DgcMdc.put(MDC_PROP_PARSER_STATE, parser.getParserState().name());
            log.error("TrustAnchor Verification failed.");
            return false;
        }

        if (!parser.isSignatureVerified()) {
            log.error("TrustAnchor Verification failed: Signature is not matching signed Trusted Issuer");
            return false;
        }

        log.debug("Got {} TrustAnchors for Integrity Check: {}", trustAnchors.size(), trustAnchors.stream()
            .map(trustAnchor -> trustAnchor.getSubject().toString())
            .collect(Collectors.joining("; ")));
        boolean trustAnchorMatch = trustAnchors.stream()
            .anyMatch(trustAnchor -> parser.getSigningCertificate().equals(trustAnchor));

        if (trustAnchorMatch) {
            return true;
        } else {
            log.error("TrustAnchor Verification failed: TrustedIssuer was not signed by known TrustAnchor");
            return false;
        }
    }

    private String getHashData(TrustedIssuerEntity entity) {
        return entity.getUuid() + HASH_SEPARATOR
            + entity.getCountry() + HASH_SEPARATOR
            + entity.getName() + HASH_SEPARATOR
            + entity.getUrl() + HASH_SEPARATOR
            + entity.getUrlType().name() + HASH_SEPARATOR;
    }
}
