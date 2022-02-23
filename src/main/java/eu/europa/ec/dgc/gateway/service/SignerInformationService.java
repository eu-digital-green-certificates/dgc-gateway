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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class SignerInformationService {

    private final TrustedPartyService trustedPartyService;

    private final CertificateUtils certificateUtils;

    private final SignerInformationRepository signerInformationRepository;

    private final DgcConfigProperties configProperties;

    private final ObjectMapper objectMapper;

    private static final String MDC_PROP_UPLOAD_CERT_THUMBPRINT = "uploadCertThumbprint";
    private static final String MDC_PROP_CSCA_CERT_THUMBPRINT = "cscaCertThumbprint";

    /**
     * Method to query persistence layer for all stored non federated SignerInformation.
     *
     * @return List of SignerInformation
     */
    public List<SignerInformationEntity> getNonFederatedSignerInformation() {
        return signerInformationRepository.getAllBySourceGatewayIsNull();
    }

    /**
     * Method to query persistence layer for SignerInformation filtered by Type.
     *
     * @param type type to filter for
     * @return List of SignerInformation
     */
    public List<SignerInformationEntity> getNonFederatedSignerInformation(
        SignerInformationEntity.CertificateType type) {
        return signerInformationRepository.getByCertificateTypeAndSourceGatewayIsNull(type);
    }

    /**
     * Method to query persistence layer for SignerInformation filtered by Type and Country.
     *
     * @param countryCode 2-digit country Code to filter for.
     * @param type        type to filter for
     * @return List of SignerInformation
     */
    public List<SignerInformationEntity> getNonFederatedSignerInformation(
        String countryCode,
        SignerInformationEntity.CertificateType type) {
        return signerInformationRepository.getByCertificateTypeAndCountryAndSourceGatewayIsNull(type, countryCode);
    }

    /**
     * Method to query persistence layer for all stored non federated SignerInformation matching given criteria.
     *
     * @return List of SignerInformation
     */
    public List<SignerInformationEntity> getSignerInformation(
        List<String> groups, List<String> country, List<String> domain, boolean withFederation) {

        final List<SignerInformationEntity.CertificateType> types = new ArrayList<>();
        if (groups != null) {
            groups.forEach(group -> {
                if (SignerInformationEntity.CertificateType.stringValues().contains(group)) {
                    types.add(SignerInformationEntity.CertificateType.valueOf(group));
                }
            });
        }

        if (withFederation) {
            return signerInformationRepository.search(
                types, types.isEmpty(),
                country, country == null || country.isEmpty(),
                domain, domain == null || domain.isEmpty());
        } else {
            return signerInformationRepository.searchNonFederated(
                types, types.isEmpty(),
                country, country == null || country.isEmpty(),
                domain, domain == null || domain.isEmpty());
        }
    }

    /**
     * Adds a new Trusted Certificate to TrustStore DB.
     *
     * @param uploadedCertificate      the certificate to add
     * @param signerCertificate        the certificate which was used to sign the message
     * @param signature                the detached signature of cms message
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @param kid                      Optional custom KID
     * @param group                    Group (Certificate Type)
     * @param domain                   Domain the certificate belongs to
     * @param properties               Map with custom properties assigned to the certificate
     * @return created Entity
     * @throws SignerCertCheckException if something went wrong
     */
    public SignerInformationEntity addTrustedCertificate(
        X509CertificateHolder uploadedCertificate,
        X509CertificateHolder signerCertificate,
        String signature,
        String authenticatedCountryCode,
        String kid,
        String group,
        String domain,
        Map<String, String> properties
    ) throws SignerCertCheckException {

        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        if (group == null || group.equals("DSC")) {
            contentCheckCountryOfOrigin(uploadedCertificate, authenticatedCountryCode);
        }
        contentCheckOneOf(group, SignerInformationEntity.CertificateType.stringValues());
        contentCheckOneOf(domain, configProperties.getTrustedCertificates().getAllowedDomains());
        for (String key : properties.keySet()) {
            contentCheckOneOf(key, configProperties.getTrustedCertificates().getAllowedProperties());
        }
        contentCheckCsca(uploadedCertificate, authenticatedCountryCode);
        contentCheckAlreadyExists(uploadedCertificate);
        contentCheckKidAlreadyExists(uploadedCertificate, kid);

        // All checks passed --> Save to DB
        byte[] certRawData;
        try {
            certRawData = uploadedCertificate.getEncoded();
        } catch (IOException e) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED, "Internal Server Error");
        }

        SignerInformationEntity newSignerInformation = new SignerInformationEntity();
        newSignerInformation.setCountry(authenticatedCountryCode);
        newSignerInformation.setRawData(Base64.getEncoder().encodeToString(certRawData));
        newSignerInformation.setThumbprint(certificateUtils.getCertThumbprint(uploadedCertificate));
        newSignerInformation.setCertificateType(SignerInformationEntity.CertificateType.DSC);
        newSignerInformation.setSignature(signature);
        newSignerInformation.setKid(kid);
        newSignerInformation.setDomain(domain == null ? "DCC" : domain);
        if (group != null) {
            newSignerInformation.setCertificateType(SignerInformationEntity.CertificateType.valueOf(group));
        }
        if (!properties.isEmpty()) {
            try {
                newSignerInformation.setProperties(objectMapper.writeValueAsString(properties));
            } catch (JsonProcessingException e) {
                throw new SignerCertCheckException(SignerCertCheckException.Reason.PROPERTY_SERIALIZATION_FAILED,
                    "Failed to serialize properties.");
            }
        }

        log.info("Saving new SignerInformation Entity");

        newSignerInformation = signerInformationRepository.save(newSignerInformation);

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);
        DgcMdc.remove(MDC_PROP_CSCA_CERT_THUMBPRINT);

        return newSignerInformation;
    }

    /**
     * Adds a new Trusted Signer Certificate to TrustStore DB.
     *
     * @param uploadedCertificate      the certificate to add
     * @param signerCertificate        the certificate which was used to sign the message
     * @param signature                the detached signature of cms message
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @throws SignerCertCheckException if validation check has failed. The exception contains
     *                                  a reason property with detailed information why the validation has failed.
     */
    public SignerInformationEntity addSignerCertificate(
        X509CertificateHolder uploadedCertificate,
        X509CertificateHolder signerCertificate,
        String signature,
        String authenticatedCountryCode
    ) throws SignerCertCheckException {

        return addTrustedCertificate(
            uploadedCertificate,
            signerCertificate,
            signature,
            authenticatedCountryCode,
            null,
            null,
            null,
            Collections.emptyMap());
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
     * @throws SignerCertCheckException if insert failed.
     */
    public SignerInformationEntity addFederatedSignerCertificate(
        String base64EncodedCertificate,
        String signature,
        String countryCode,
        String kid,
        FederationGatewayEntity sourceGateway
    ) throws SignerCertCheckException {

        X509CertificateHolder certificate;
        try {
            certificate = new X509CertificateHolder(
                Base64.getDecoder().decode(base64EncodedCertificate)
            );
        } catch (IOException e) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED,
                "Failed to decode Raw Cert");
        }

        contentCheckAlreadyExists(certificate);

        SignerInformationEntity newSignerInformation = new SignerInformationEntity();
        newSignerInformation.setSourceGateway(sourceGateway);
        newSignerInformation.setKid(kid);
        newSignerInformation.setCountry(countryCode);
        newSignerInformation.setRawData(base64EncodedCertificate);
        newSignerInformation.setThumbprint(certificateUtils.getCertThumbprint(certificate));
        newSignerInformation.setCertificateType(SignerInformationEntity.CertificateType.DSC);
        newSignerInformation.setSignature(signature);

        log.info("Saving Federated SignerInformation Entity");

        return signerInformationRepository.save(newSignerInformation);
    }

    /**
     * Deletes a Trusted Signer Certificate from TrustStore DB.
     *
     * @param uploadedCertificate      the certificate to delete
     * @param signerCertificate        the certificate which was used to sign the message
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @throws SignerCertCheckException if validation check has failed. The exception contains
     *                                  a reason property with detailed information why the validation has failed.
     */
    public void deleteSignerCertificate(
        X509CertificateHolder uploadedCertificate,
        X509CertificateHolder signerCertificate,
        String authenticatedCountryCode
    ) throws SignerCertCheckException {

        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        contentCheckCountryOfOrigin(uploadedCertificate, authenticatedCountryCode);
        contentCheckExists(uploadedCertificate);

        log.info("Revoking SignerInformation Entity");

        // All checks passed --> Delete from DB
        signerInformationRepository.deleteByThumbprint(certificateUtils.getCertThumbprint(uploadedCertificate));

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);
    }

    /**
     * Deletes SignerCertificates by given GatewayId.
     *
     * @param gatewayId GatewayID of the certificates to delete.
     */
    public void deleteSignerCertificateByFederationGateway(String gatewayId) {
        log.info("Deleting SignerInformation by GatewayId {}", gatewayId);

        Long deleteCount = signerInformationRepository.deleteBySourceGatewayGatewayId(gatewayId);

        log.info("Deleted {} SignerInformation with GatewayId {}", deleteCount, gatewayId);
    }

    /**
     * Extracts X509Certificate from {@link SignerInformationEntity}.
     *
     * @param signerInformationEntity entity from which the certificate should be extracted.
     * @return X509Certificate representation.
     */
    public X509Certificate getX509CertificateFromEntity(SignerInformationEntity signerInformationEntity) {
        try {
            byte[] rawDataBytes = Base64.getDecoder().decode(signerInformationEntity.getRawData());
            return certificateUtils.convertCertificate(new X509CertificateHolder(rawDataBytes));
        } catch (Exception e) {
            log.error("Failed to parse Certificate from SignerInformationEntity", e);
        }

        return null;
    }

    private void contentCheckOneOf(String value, List<String> allowedValues) throws SignerCertCheckException {
        if (value == null) {
            return;
        }

        if (allowedValues.stream().noneMatch(value::equals)) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.PROPERTY_NOT_ALLOWED,
                String.format("Property Key or Value %s is not allowed. Allowed Values are: %s",
                    value, String.join(", ", allowedValues)));
        }
    }

    private void contentCheckUploaderCertificate(
        X509CertificateHolder signerCertificate,
        String authenticatedCountryCode) throws SignerCertCheckException {
        // Content Check Step 1: Uploader Certificate
        String signerCertThumbprint = certificateUtils.getCertThumbprint(signerCertificate);
        Optional<TrustedPartyEntity> certFromDb = trustedPartyService.getCertificate(
            signerCertThumbprint,
            authenticatedCountryCode,
            TrustedPartyEntity.CertificateType.UPLOAD
        );

        if (certFromDb.isEmpty()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOADER_CERT_CHECK_FAILED,
                "Could not find upload certificate with hash %s and country %s",
                signerCertThumbprint, authenticatedCountryCode);
        }

        DgcMdc.put(MDC_PROP_UPLOAD_CERT_THUMBPRINT, signerCertThumbprint);
    }

    private void contentCheckCountryOfOrigin(X509CertificateHolder uploadedCertificate,
                                             String authenticatedCountryCode) throws SignerCertCheckException {

        // Content Check Step 2: Country of Origin check
        RDN[] uploadedCertCountryProperties =
            uploadedCertificate.getSubject().getRDNs(X509ObjectIdentifiers.countryName);

        if (uploadedCertCountryProperties.length > 1) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED,
                "Uploaded certificate contains more than one country property.");
        } else if (uploadedCertCountryProperties.length < 1) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED,
                "Uploaded certificate contains no country property.");
        }

        if (!uploadedCertCountryProperties[0].getFirst().getValue().toString().equals(authenticatedCountryCode)) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED,
                "Uploaded certificate is not issued for uploader country.");
        }
    }

    private void contentCheckCsca(X509CertificateHolder uploadedCertificate,
                                  String authenticatedCountryCode) throws SignerCertCheckException {

        // Content Check Step 3: CSCA Check
        List<TrustedPartyEntity> trustedCas =
            trustedPartyService.getCertificate(authenticatedCountryCode, TrustedPartyEntity.CertificateType.CSCA);

        if (trustedCas.isEmpty()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.CSCA_CHECK_FAILED,
                "CSCA list for country %s is empty", authenticatedCountryCode);
        }

        Optional<TrustedPartyEntity> matchingCa = trustedCas.stream()
            .dropWhile(ca -> !certificateSignedByCa(uploadedCertificate, ca))
            .findFirst();

        if (matchingCa.isEmpty()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.CSCA_CHECK_FAILED,
                "Could not verify uploaded certificate was signed by valid CSCA.");
        } else {
            DgcMdc.put(MDC_PROP_CSCA_CERT_THUMBPRINT, matchingCa.get().getThumbprint());
        }
    }

    private void contentCheckAlreadyExists(X509CertificateHolder uploadedCertificate) throws SignerCertCheckException {

        String uploadedCertificateThumbprint = certificateUtils.getCertThumbprint(uploadedCertificate);
        Optional<SignerInformationEntity> signerInformationEntity =
            signerInformationRepository.getFirstByThumbprint(uploadedCertificateThumbprint);

        if (signerInformationEntity.isPresent()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.ALREADY_EXIST_CHECK_FAILED,
                "Uploaded certificate already exists");
        }
    }

    private void contentCheckKidAlreadyExists(X509CertificateHolder uploadedCertificate, String customKid)
        throws SignerCertCheckException {

        String kid = customKid;
        if (customKid == null) {
            // Custom Kid not provided, using the first 8 byte of hash as fallback.
            String uploadedCertificateThumbprint = certificateUtils.getCertThumbprint(uploadedCertificate);
            kid = uploadedCertificateThumbprint.substring(0, 16);
        }

        Optional<SignerInformationEntity> signerInformationEntity =
            signerInformationRepository.getFirstByThumbprintStartsWith(kid);

        if (signerInformationEntity.isPresent()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.KID_CHECK_FAILED,
                "A certificate with KID of uploaded certificate already exists");
        }

        signerInformationEntity = signerInformationRepository.getFirstByKid(kid);

        if (signerInformationEntity.isPresent()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.KID_CHECK_FAILED,
                "A certificate with KID of uploaded certificate already exists");
        }
    }

    private void contentCheckExists(X509CertificateHolder uploadedCertificate) throws SignerCertCheckException {

        String uploadedCertificateThumbprint = certificateUtils.getCertThumbprint(uploadedCertificate);
        Optional<SignerInformationEntity> signerInformationEntity =
            signerInformationRepository.getFirstByThumbprint(uploadedCertificateThumbprint);

        if (signerInformationEntity.isEmpty()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.EXIST_CHECK_FAILED,
                "Uploaded certificate does not exists");
        }
    }

    private boolean certificateSignedByCa(X509CertificateHolder certificate, TrustedPartyEntity caCertificateEntity) {
        X509Certificate caCertificate = trustedPartyService.getX509CertificateFromEntity(caCertificateEntity);

        ContentVerifierProvider verifier;
        try {
            verifier = new JcaContentVerifierProviderBuilder().build(caCertificate);
        } catch (OperatorCreationException e) {
            DgcMdc.put("certHash", caCertificateEntity.getThumbprint());
            log.error("Failed to instantiate JcaContentVerifierProvider from cert");
            return false;
        }

        try {
            return certificate.isSignatureValid(verifier);
        } catch (CertException | RuntimeOperatorException e) {
            return false;
        }
    }

    public static class SignerCertCheckException extends Exception {

        @Getter
        private final Reason reason;

        public SignerCertCheckException(Reason reason, String message, Object... args) {
            super(String.format(message, args));
            this.reason = reason;
        }

        public enum Reason {
            UPLOADER_CERT_CHECK_FAILED,
            COUNTRY_OF_ORIGIN_CHECK_FAILED,
            CSCA_CHECK_FAILED,
            ALREADY_EXIST_CHECK_FAILED,
            KID_CHECK_FAILED,
            EXIST_CHECK_FAILED,
            UPLOAD_FAILED,
            PROPERTY_NOT_ALLOWED,
            PROPERTY_SERIALIZATION_FAILED
        }
    }
}
