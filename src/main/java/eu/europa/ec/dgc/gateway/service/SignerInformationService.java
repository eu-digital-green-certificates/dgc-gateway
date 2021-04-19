package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class SignerInformationService {

    private final CertificateService certificateService;

    private final CertificateUtils certificateUtils;

    private final SignerInformationRepository signerInformationRepository;

    public SignerInformationEntity addSignerCertificate(
        X509CertificateHolder uploadedCertificate,
        X509CertificateHolder signerCertificate,
        String rawCmsMessage,
        String authenticatedCountryCode
    ) throws SignerCertCheckException {

        // Content Check Step 1: Uploader Certificate
        String signerCertThumbprint = certificateUtils.getCertThumbprint(signerCertificate);
        Optional<TrustedPartyEntity> certFromDb = certificateService.getCertificate(
            signerCertThumbprint,
            authenticatedCountryCode,
            TrustedPartyEntity.CertificateType.UPLOAD
        );

        if (certFromDb.isEmpty()) {
            log.error("Could not find upload certificate with hash {} and country {}",
                signerCertThumbprint, authenticatedCountryCode);
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOADER_CERT_CHECK_FAILED);
        }

        // Content Check Step 2: Country of Origin check
        RDN[] uploadedCertCountryProperties =
            uploadedCertificate.getSubject().getRDNs(X509ObjectIdentifiers.countryName);

        if (uploadedCertCountryProperties.length > 1) {
            log.error("Uploaded certificate contains more than one country property.");
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED);
        } else if (uploadedCertCountryProperties.length < 1) {
            log.error("Uploaded certificate contains no country property.");
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED);
        }

        if (!uploadedCertCountryProperties[0].getFirst().getValue().toString().equals(authenticatedCountryCode)) {
            log.error("Uploaded certificate is not issued for uploader country.");
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED);
        }

        // Content Check Step 3: CSCA Check
        List<TrustedPartyEntity> trustedCas =
            certificateService.getCertificates(authenticatedCountryCode, TrustedPartyEntity.CertificateType.CSCA);

        if (trustedCas.isEmpty()) {
            log.error("CSCA list for country {} is empty", authenticatedCountryCode);
            throw new SignerCertCheckException(SignerCertCheckException.Reason.CSCA_CHECK_FAILED);
        }

        boolean cscaCheckResult = trustedCas.stream().anyMatch(ca -> certificateSignedByCa(uploadedCertificate, ca));
        if (!cscaCheckResult) {
            log.error("Could not verify uploaded certificate was signed by valid CSCA");
            throw new SignerCertCheckException(SignerCertCheckException.Reason.CSCA_CHECK_FAILED);
        }

        // Content Check Step 4: Already Exist Check
        String uploadedCertificateThumbprint = certificateUtils.getCertThumbprint(uploadedCertificate);
        Optional<SignerInformationEntity> signerInformationEntity =
            signerInformationRepository.getFirstByThumbprint(uploadedCertificateThumbprint);

        if (signerInformationEntity.isPresent()) {
            log.error("Uploaded certificate already exists");
            throw new SignerCertCheckException(SignerCertCheckException.Reason.ALREADY_EXIST_CHECK_FAILED);
        }

        // All checks passed --> Save to DB
        byte[] certRawData;
        try {
            certRawData = uploadedCertificate.getEncoded();
        } catch (IOException e) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED);
        }

        SignerInformationEntity newSignerInformation = new SignerInformationEntity();
        newSignerInformation.setCountry(authenticatedCountryCode);
        newSignerInformation.setRawData(Base64.getEncoder().encodeToString(certRawData));
        newSignerInformation.setThumbprint(uploadedCertificateThumbprint);
        newSignerInformation.setCertificateType(SignerInformationEntity.CertificateType.DSC);
        newSignerInformation.setSignature(rawCmsMessage);

        return signerInformationRepository.save(newSignerInformation);
    }

    private boolean certificateSignedByCa(X509CertificateHolder certificate, TrustedPartyEntity caCertificateEntity) {
        X509Certificate caCertificate = certificateService.getX509CertificateFromEntity(caCertificateEntity);

        ContentVerifierProvider verifier;
        try {
            verifier = new JcaContentVerifierProviderBuilder().build(caCertificate);
        } catch (OperatorCreationException e) {
            log.error("Failed to instantiate JcaContentVerifierProvider from cert {}",
                caCertificateEntity.getThumbprint());
            return false;
        }

        try {
            return certificate.isSignatureValid(verifier);
        } catch (CertException e) {
            log.error("Could not verify certificate issuance.");
            return false;
        }
    }

    public static class SignerCertCheckException extends Exception {
        Reason reason;

        public SignerCertCheckException(Reason reason) {
            super();
            this.reason = reason;
        }

        public enum Reason {
            UPLOADER_CERT_CHECK_FAILED,
            COUNTRY_OF_ORIGIN_CHECK_FAILED,
            CSCA_CHECK_FAILED,
            ALREADY_EXIST_CHECK_FAILED,
            UPLOAD_FAILED
        }
    }
}
