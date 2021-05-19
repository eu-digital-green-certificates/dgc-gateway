/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
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

import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
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

    /**
     * Method to query persistence layer for all stored SignerInformation.
     *
     * @return List of SignerInformation
     */
    public List<SignerInformationEntity> getSignerInformation() {
        return signerInformationRepository.findAll();
    }

    /**
     * Method to query persistence layer for SignerInformation filtered by Type.
     *
     * @param type type to filter for
     * @return List of SignerInformation
     */
    public List<SignerInformationEntity> getSignerInformation(SignerInformationEntity.CertificateType type) {
        return signerInformationRepository.getByCertificateType(type);
    }

    /**
     * Method to query persistence layer for SignerInformation filtered by Type and Country.
     *
     * @param countryCode 2-digit country Code to filter for.
     * @param type        type to filter for
     * @return List of SignerInformation
     */
    public List<SignerInformationEntity> getSignerInformation(
        String countryCode,
        SignerInformationEntity.CertificateType type) {
        return signerInformationRepository.getByCertificateTypeAndCountry(type, countryCode);
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

        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        contentCheckCountryOfOrigin(uploadedCertificate, authenticatedCountryCode);
        contentCheckCsca(uploadedCertificate, authenticatedCountryCode);
        contentCheckAlreadyExists(uploadedCertificate);

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

        // All checks passed --> Delete from DB
        signerInformationRepository.deleteByThumbprint(certificateUtils.getCertThumbprint(uploadedCertificate));
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
            trustedPartyService.getCertificates(authenticatedCountryCode, TrustedPartyEntity.CertificateType.CSCA);

        if (trustedCas.isEmpty()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.CSCA_CHECK_FAILED,
                "CSCA list for country %s is empty", authenticatedCountryCode);
        }

        boolean cscaCheckResult = trustedCas.stream().anyMatch(ca -> certificateSignedByCa(uploadedCertificate, ca));
        if (!cscaCheckResult) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.CSCA_CHECK_FAILED,
                "Could not verify uploaded certificate was signed by valid CSCA.");
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
            EXIST_CHECK_FAILED,
            UPLOAD_FAILED
        }
    }
}
