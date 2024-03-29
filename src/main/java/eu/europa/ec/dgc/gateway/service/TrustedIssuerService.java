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

package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
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
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TrustedIssuerService {

    private static final String MDC_PROP_ISSUER_UUID = "issuerUuid";

    private static final String MDC_PROP_PARSER_STATE = "parserState";

    private static final String HASH_SEPARATOR = ";";

    private final TrustedIssuerRepository trustedIssuerRepository;

    @Qualifier("trustAnchor")
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
    public List<TrustedIssuerEntity> getAllIssuers(final List<String> countryCodes) {
        return trustedIssuerRepository.getAllByCountryIn(countryCodes)
            .stream()
            .filter(this::validateTrustedIssuerIntegrity)
            .collect(Collectors.toList());
    }

    private boolean validateTrustedIssuerIntegrity(TrustedIssuerEntity trustedIssuerEntity) {

        DgcMdc.put(MDC_PROP_ISSUER_UUID, trustedIssuerEntity.getId());

        if (StringUtils.isEmpty(trustedIssuerEntity.getSignature())) {
            log.error("Certificate entity does not contain raw certificate or certificate signature.");
            return false;
        }

        X509CertificateHolder trustAnchor = null;
        try {
            trustAnchor = certificateUtils.convertCertificate((X509Certificate) trustAnchorKeyStore.getCertificate(
                dgcConfigProperties.getTrustAnchor().getCertificateAlias()));
        } catch (KeyStoreException | CertificateEncodingException | IOException e) {
            log.error("Could not load DGCG-TrustAnchor from KeyStore.", e);
            return false;
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

        if (!parser.getSigningCertificate().equals(trustAnchor)) {
            log.error("TrustAnchor Verification failed: Trusted Issuer was not signed by known TrustAnchor");
            return false;
        }

        return true;
    }

    private String getHashData(TrustedIssuerEntity entity) {
        return entity.getCountry() + HASH_SEPARATOR
            + entity.getName() + HASH_SEPARATOR
            + entity.getUrl() + HASH_SEPARATOR
            + entity.getUrlType().name() + HASH_SEPARATOR;
    }
}
