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
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedPartyRepository;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.gateway.utils.ListUtils;
import eu.europa.ec.dgc.signing.SignedCertificateMessageParser;
import eu.europa.ec.dgc.signing.SignedMessageParser;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TrustedPartyService {

    private static final String MDC_PROP_CERT_THUMBPRINT = "certVerifyThumbprint";
    private static final String MDC_PROP_PARSER_STATE = "parserState";
    private final TrustedPartyRepository trustedPartyRepository;
    private final KeyStore trustAnchorKeyStore;
    private final DgcConfigProperties dgcConfigProperties;
    private final CertificateUtils certificateUtils;

    /**
     * Method to query the db for all certificates.
     *
     * @return List holding the found certificates.
     */
    public List<TrustedPartyEntity> getCertificates() {

        return trustedPartyRepository.findAll()
            .stream()
            .filter(this::validateCertificateIntegrity)
            .collect(Collectors.toList());
    }

    /**
     * Method to query the db for certificates by type.
     *
     * @param type type to filter for.
     * @return List holding the found certificates.
     */
    public List<TrustedPartyEntity> getCertificates(TrustedPartyEntity.CertificateType type) {

        return trustedPartyRepository.getByCertificateType(type)
            .stream()
            .filter(this::validateCertificateIntegrity)
            .collect(Collectors.toList());
    }

    /**
     * Method to query the db for certificates.
     *
     * @param country country of certificate.
     * @param type    type of certificate.
     * @return List holding the found certificates.
     */
    public List<TrustedPartyEntity> getCertificates(String country, TrustedPartyEntity.CertificateType type) {

        return trustedPartyRepository.getByCountryAndCertificateType(country, type)
            .stream()
            .filter(this::validateCertificateIntegrity)
            .collect(Collectors.toList());
    }

    /**
     * Finds a list of Certificates.
     * Optional the list can be filtered by a timestamp and paginated.
     *
     * @param ifModifiedSinceTimestamp since timestamp for filtering Certificate.
     * @param page zero-based page index, must NOT be negative.
     * @param size number of items in a page to be returned, must be greater than 0.
     * @return List of certificates.
     */
    public List<TrustedPartyEntity> getCertificates(Long ifModifiedSinceTimestamp,
                                                    Integer page, Integer size) {

        List<TrustedPartyEntity> trustedPartyEntityFullList;

        if (ifModifiedSinceTimestamp == null) {
            trustedPartyEntityFullList = trustedPartyRepository.findAll()
                .stream()
                .filter(this::validateCertificateIntegrity)
                .collect(Collectors.toList());

        } else {
            trustedPartyEntityFullList =
                trustedPartyRepository.getIsSince(epochMillisToZonedDateTime(ifModifiedSinceTimestamp))
                    .stream()
                    .filter(this::validateCertificateIntegrity)
                    .collect(Collectors.toList());
        }
        if (page != null && size != null) {
            return ListUtils.getPage(trustedPartyEntityFullList, page, size);
        } else {
            return trustedPartyEntityFullList;
        }
    }

    /**
     * Finds a list of Certificates  by type.
     * Optional the list can be filtered by a timestamp and paginated.
     *
     * @param type type to filter for.
     * @param ifModifiedSinceTimestamp since timestamp for filtering Certificate.
     * @param page zero-based page index, must NOT be negative.
     * @param size number of items in a page to be returned, must be greater than 0.
     * @return List of certificates.
     */
    public List<TrustedPartyEntity> getCertificates(TrustedPartyEntity.CertificateType type,
                                                    Long ifModifiedSinceTimestamp,
                                                    Integer page, Integer size) {

        List<TrustedPartyEntity> trustedPartyEntityByTypeList;

        if (ifModifiedSinceTimestamp == null) {
            trustedPartyEntityByTypeList = trustedPartyRepository.getByCertificateType(type)
                .stream()
                .filter(this::validateCertificateIntegrity)
                .collect(Collectors.toList());

        } else {
            trustedPartyEntityByTypeList =
                trustedPartyRepository.getByCertificateTypeIsSince(
                    type,epochMillisToZonedDateTime(ifModifiedSinceTimestamp))
                    .stream()
                    .filter(this::validateCertificateIntegrity)
                    .collect(Collectors.toList());
        }
        if (page != null && size != null) {
            return ListUtils.getPage(trustedPartyEntityByTypeList, page, size);
        } else {
            return trustedPartyEntityByTypeList;
        }
    }

    /**
     * Finds a list of Certificates by type.
     * Optional the list can be filtered by a timestamp and paginated.
     *
     * @param country country of certificate.
     * @param type type to filter for.
     * @param ifModifiedSinceTimestamp since timestamp for filtering Certificate.
     * @param page zero-based page index, must NOT be negative.
     * @param size number of items in a page to be returned, must be greater than 0.
     * @return List of certificates.
     */
    public List<TrustedPartyEntity> getCertificates(String country,
                                                    TrustedPartyEntity.CertificateType type,
                                                    Long ifModifiedSinceTimestamp,
                                                    Integer page, Integer size) {

        List<TrustedPartyEntity> trustedPartyEntityByTypeAndCountryList;

        if (ifModifiedSinceTimestamp == null) {
            trustedPartyEntityByTypeAndCountryList =
                trustedPartyRepository.getByCountryAndCertificateType(country, type)
                    .stream()
                    .filter(this::validateCertificateIntegrity)
                    .collect(Collectors.toList());

        } else {
            trustedPartyEntityByTypeAndCountryList =
                trustedPartyRepository.getByCountryAndCertificateTypeIsSince(country,
                        type, epochMillisToZonedDateTime(ifModifiedSinceTimestamp))
                    .stream()
                    .filter(this::validateCertificateIntegrity)
                    .collect(Collectors.toList());
        }
        if (page != null && size != null) {
            return ListUtils.getPage(trustedPartyEntityByTypeAndCountryList, page, size);
        } else {
            return trustedPartyEntityByTypeAndCountryList;
        }
    }

    /**
     * Method to query the db for a certificate.
     *
     * @param thumbprint RSA-256 thumbprint of certificate.
     * @param country    country of certificate.
     * @param type       type of certificate.
     * @return Optional holding the certificate if found.
     */
    public Optional<TrustedPartyEntity> getCertificate(
        String thumbprint, String country, TrustedPartyEntity.CertificateType type) {

        return trustedPartyRepository.getFirstByThumbprintAndCountryAndCertificateType(thumbprint, country, type)
            .map(trustedPartyEntity -> validateCertificateIntegrity(trustedPartyEntity) ? trustedPartyEntity : null);
    }

    /**
     * Returns a list of onboarded countries.
     *
     * @return List of String.
     */
    public List<String> getCountryList() {
        return trustedPartyRepository.getCountryCodeList();
    }

    private static ZonedDateTime epochMillisToZonedDateTime(long epochMilliSeconds) {
        return ZonedDateTime.ofInstant(
            Instant.ofEpochMilli(epochMilliSeconds), ZoneOffset.systemDefault());
    }

    private boolean validateCertificateIntegrity(TrustedPartyEntity trustedPartyEntity) {

        DgcMdc.put(MDC_PROP_CERT_THUMBPRINT, trustedPartyEntity.getThumbprint());

        // check if entity has signature and certificate information
        if (trustedPartyEntity.getSignature() == null || trustedPartyEntity.getSignature().isEmpty()
            || trustedPartyEntity.getRawData() == null || trustedPartyEntity.getRawData().isEmpty()) {
            log.error("Certificate entity does not contain raw certificate or certificate signature.");
            return false;
        }

        // check if raw data contains a x509 certificate
        X509Certificate x509Certificate = getX509CertificateFromEntity(trustedPartyEntity);
        if (x509Certificate == null) {
            log.error("Raw certificate data does not contain a valid x509Certificate.");
            return false;
        }

        // verify if thumbprint in database matches the certificate in raw data
        if (!verifyThumbprintMatchesCertificate(trustedPartyEntity, x509Certificate)) {
            log.error("Thumbprint in database does not match thumbprint of stored certificate.");
            return false;
        }

        // load DGCG Trust Anchor PublicKey from KeyStore
        X509CertificateHolder trustAnchor = null;
        try {
            trustAnchor = certificateUtils.convertCertificate((X509Certificate) trustAnchorKeyStore.getCertificate(
                dgcConfigProperties.getTrustAnchor().getCertificateAlias()));
        } catch (KeyStoreException | CertificateEncodingException | IOException e) {
            log.error("Could not load DGCG-TrustAnchor from KeyStore.", e);
            return false;
        }

        // verify certificate signature
        SignedCertificateMessageParser parser =
            new SignedCertificateMessageParser(trustedPartyEntity.getSignature(), trustedPartyEntity.getRawData());

        if (parser.getParserState() != SignedMessageParser.ParserState.SUCCESS) {
            DgcMdc.put(MDC_PROP_PARSER_STATE, parser.getParserState().name());
            log.error("TrustAnchor Verification failed.");
            return false;
        }

        if (!parser.isSignatureVerified()) {
            log.error("TrustAnchor Verification failed: Signature is not matching signed certificate");
            return false;
        }

        if (!parser.getSigningCertificate().equals(trustAnchor)) {
            log.error("TrustAnchor Verification failed: Certificate was not signed by known TrustAnchor");
            return false;
        }

        return true;
    }


    /**
     * Extracts X509Certificate from {@link TrustedPartyEntity}.
     *
     * @param trustedPartyEntity entity from which the certificate should be extraced.
     * @return X509Certificate representation.
     */
    public X509Certificate getX509CertificateFromEntity(TrustedPartyEntity trustedPartyEntity) {
        try {
            byte[] rawDataBytes = Base64.getDecoder().decode(trustedPartyEntity.getRawData());
            return certificateUtils.convertCertificate(new X509CertificateHolder(rawDataBytes));
        } catch (Exception e) {
            log.error("Raw certificate data does not contain a valid x509Certificate", e);
        }

        return null;
    }

    private boolean verifyThumbprintMatchesCertificate(
        TrustedPartyEntity trustedPartyEntity, X509Certificate certificate) {
        String certHash = certificateUtils.getCertThumbprint(certificate);

        return certHash != null && certHash.equals(trustedPartyEntity.getThumbprint());
    }
}
