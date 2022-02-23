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
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedPartyRepository;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.signing.SignedCertificateMessageParser;
import eu.europa.ec.dgc.signing.SignedMessageParser;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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
    public List<TrustedPartyEntity> getNonFederatedTrustedParties() {

        return trustedPartyRepository.getBySourceGatewayIsNull()
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
    public List<TrustedPartyEntity> getNonFederatedTrustedParties(TrustedPartyEntity.CertificateType type) {

        return trustedPartyRepository.getByCertificateTypeAndSourceGatewayIsNull(type)
            .stream()
            .filter(this::validateCertificateIntegrity)
            .collect(Collectors.toList());
    }

    /**
     * Method to query the db for trusted parties matching given criteria.
     *
     * @return List of TrustedPartyEntity
     */
    public List<TrustedPartyEntity> getTrustedParties(
        List<String> groups, List<String> country, List<String> domain, boolean withFederation) {

        final List<TrustedPartyEntity.CertificateType> types = new ArrayList<>();
        if (groups != null) {
            groups.forEach(group -> {
                if (TrustedPartyEntity.CertificateType.stringValues().contains(group)) {
                    types.add(TrustedPartyEntity.CertificateType.valueOf(group));
                }
            });
        }

        if (withFederation) {
            return trustedPartyRepository.search(
                    types, types.isEmpty(),
                    country, country == null || country.isEmpty(),
                    domain, domain == null || domain.isEmpty())
                .stream()
                .filter(this::validateCertificateIntegrity)
                .collect(Collectors.toList());
        } else {
            return trustedPartyRepository.searchNonFederated(
                    types, types.isEmpty(),
                    country, country == null || country.isEmpty(),
                    domain, domain == null || domain.isEmpty())
                .stream()
                .filter(this::validateCertificateIntegrity)
                .collect(Collectors.toList());
        }
    }

    /**
     * Method to query the db for certificates.
     *
     * @param country country of certificate.
     * @param type    type of certificate.
     * @return List holding the found certificates.
     */
    public List<TrustedPartyEntity> getCertificate(String country, TrustedPartyEntity.CertificateType type) {

        return trustedPartyRepository.getByCountryAndCertificateType(country, type)
            .stream()
            .filter(this::validateCertificateIntegrity)
            .collect(Collectors.toList());
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

    /**
     * Validate the integrity of the certificate used to sign the trusted party.
     */
    public boolean validateCertificateIntegrity(TrustedPartyEntity trustedPartyEntity) {

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
        List<X509CertificateHolder> trustAnchors = new ArrayList<>();
        if (trustedPartyEntity.getSourceGateway() == null) {
            log.debug("TrustedParty is not federated, using TrustAnchor from Keystore");
            try {
                trustAnchors.add(
                    certificateUtils.convertCertificate((X509Certificate) trustAnchorKeyStore.getCertificate(
                        dgcConfigProperties.getTrustAnchor().getCertificateAlias())));
            } catch (KeyStoreException | CertificateEncodingException | IOException e) {
                log.error("Could not load DGCG-TrustAnchor from KeyStore.", e);
                return false;
            }
        } else {
            log.debug("TrustedParty is federated, fetching TrustAnchors from Database.");
            trustedPartyEntity.getSourceGateway().getTrustedParties().stream()
                .filter(gatewayTrustedParty -> gatewayTrustedParty.getCertificateType()
                    == TrustedPartyEntity.CertificateType.TRUSTANCHOR)
                .filter(this::validateCertificateIntegrity)
                .map(this::getX509CertificateHolderFromEntity)
                .forEach(trustAnchors::add);
        }

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

        // verify certificate signature
        log.debug("Got {} TrustAnchors for Integrity Check: {}", trustAnchors.size(), trustAnchors.stream()
            .map(trustAnchor -> trustAnchor.getSubject().toString())
            .collect(Collectors.joining("; ")));
        boolean trustAnchorMatch = trustAnchors.stream()
            .anyMatch(trustAnchor -> parser.getSigningCertificate().equals(trustAnchor));

        if (trustAnchorMatch) {
            return true;
        } else {
            log.error("TrustAnchor Verification failed: Certificate was not signed by known TrustAnchor");
            return false;
        }
    }


    /**
     * Deletes TrustedParty by given GatewayId.
     *
     * @param gatewayId GatewayID of the certificates to delete.
     */
    public void deleteTrustedPartyByByFederationGateway(String gatewayId) {
        log.info("Deleting TrustedParty by GatewayId {}", gatewayId);

        Long deleteCount = trustedPartyRepository.deleteBySourceGatewayGatewayId(gatewayId);

        log.info("Deleted {} TrustedParty with GatewayId {}", deleteCount, gatewayId);
    }

    /**
     * Insert a new federated Signer Certificate.
     *
     * @param base64EncodedCertificate Base64 encoded Certificate
     * @param signature                Upload Certificate Signature
     * @param countryCode              Country Code of uploaded certificate
     * @param kid                      KID of the certificate
     * @param sourceGateway            Gateway the cert is originated from
     * @return persisted Entity
     * @throws IOException If conversion to Certificate Object failed.
     */
    public TrustedPartyEntity addFederatedTrustedParty(
        String base64EncodedCertificate,
        String signature,
        String countryCode,
        String kid,
        TrustedPartyEntity.CertificateType type,
        FederationGatewayEntity sourceGateway
    ) throws IOException {
        X509CertificateHolder certificate = new X509CertificateHolder(
            Base64.getDecoder().decode(base64EncodedCertificate)
        );

        TrustedPartyEntity newTrustedPartyEntity = new TrustedPartyEntity();
        newTrustedPartyEntity.setSourceGateway(sourceGateway);
        newTrustedPartyEntity.setKid(kid);
        newTrustedPartyEntity.setCountry(countryCode);
        newTrustedPartyEntity.setRawData(base64EncodedCertificate);
        newTrustedPartyEntity.setThumbprint(certificateUtils.getCertThumbprint(certificate));
        newTrustedPartyEntity.setCertificateType(type);
        newTrustedPartyEntity.setSignature(signature);

        log.info("Saving Federated SignerInformation Entity");

        return trustedPartyRepository.save(newTrustedPartyEntity);
    }

    /**
     * Extracts X509Certificate from {@link TrustedPartyEntity}.
     *
     * @param trustedPartyEntity entity from which the certificate should be extracted.
     * @return X509Certificate representation.
     */
    public X509Certificate getX509CertificateFromEntity(TrustedPartyEntity trustedPartyEntity) {
        try {
            return certificateUtils.convertCertificate(getX509CertificateHolderFromEntity(trustedPartyEntity));
        } catch (Exception e) {
            log.error("Raw certificate data does not contain a valid x509Certificate", e);
        }

        return null;
    }

    /**
     * Extracts X509CertificateHolder from {@link TrustedPartyEntity}.
     *
     * @param trustedPartyEntity entity from which the certificate should be extracted.
     * @return X509CertificateHolder representation.
     */
    public X509CertificateHolder getX509CertificateHolderFromEntity(TrustedPartyEntity trustedPartyEntity) {
        try {
            byte[] rawDataBytes = Base64.getDecoder().decode(trustedPartyEntity.getRawData());
            return new X509CertificateHolder(rawDataBytes);
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
