package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.signing.SignedByteArrayMessageBuilder;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

@Service
@RequiredArgsConstructor
@Slf4j
public class PublishingService {

    private final TrustedPartyService trustedPartyService;

    private final SignerInformationService signerInformationService;

    private final CertificateUtils certificateUtils;

    private final DgcConfigProperties properties;

    @Qualifier("publication")
    private final KeyStore publicationKeyStore;

    private static final String PEM_BEGIN = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_END = "-----END CERTIFICATE-----";
    private static final String LINE_SEPERATOR = "\n";

    /**
     * Method to generate and upload an archive with all onboarded CSCA and DSC.
     */
    @Scheduled(cron = "0 0 3 * * *")
    @SchedulerLock(name = "publishing_generate_zip")
    public void publishGatewayData() {
        log.info("Start publishing of packed Gateway data");

        byte[] zip = generateArchive();
        byte[] signature = calculateSignature(zip);
        uploadGatewayData(zip, signature);

        log.info("Finished publishing of packed Gateway data");
    }

    private byte[] generateArchive() {
        log.debug("Generating Archive for Certificate Publication");

        log.debug("Fetching TrustedParty CSCA Certificates");
        List<TrustedPartyEntity> cscaTrustedParties =
            trustedPartyService.getCertificates(TrustedPartyEntity.CertificateType.CSCA);
        log.debug("Got {} trustedParty CSCA Certificates", cscaTrustedParties.size());

        log.debug("Fetching SignerInformation");
        List<SignerInformationEntity> signerInformationList = signerInformationService.getSignerInformation();
        log.debug("Fetched {} trusted SignerInformation", signerInformationList.size());

        try (
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ZipOutputStream zipOutputStream = new ZipOutputStream(byteArrayOutputStream)
        ) {
            /*
             * Add Static Files
             */
            addFile(zipOutputStream, "Readme.txt", getClasspathFileContent("Readme.txt"));
            addFile(zipOutputStream, "License.txt", getClasspathFileContent("License.txt"));
            addFile(zipOutputStream, "Version.txt", getVersionFileContent());

            /*
             * Add DSC
             */
            addDirectory(zipOutputStream, "DSC/");
            addDirectory(zipOutputStream, "DSC/DCC/");
            signerInformationList.stream()
                .map(SignerInformationEntity::getCountry)
                .distinct()
                .forEach(country -> addDirectory(zipOutputStream, "DSC/DCC/" + country + "/"));

            signerInformationList.forEach(signerInformation -> {
                X509Certificate cert = signerInformationService.getX509CertificateFromEntity(signerInformation);
                String thumbprint = certificateUtils.getCertThumbprint(cert);
                byte[] pem = getPemBytes(Base64.getDecoder().decode(signerInformation.getRawData()));
                String filename = "DSC/DCC/" + signerInformation.getCountry() + "/" + thumbprint + ".pem";
                addFile(zipOutputStream, filename, pem);
            });

            /*
             * Add CSCA
             */
            addDirectory(zipOutputStream, "CSCA/");
            addDirectory(zipOutputStream, "CSCA/DCC/");
            cscaTrustedParties.stream()
                .map(TrustedPartyEntity::getCountry)
                .distinct()
                .forEach(country -> addDirectory(zipOutputStream, "CSCA/DCC/" + country + "/"));

            cscaTrustedParties.forEach(trustedPartyEntity -> {
                X509Certificate cert = trustedPartyService.getX509CertificateFromEntity(trustedPartyEntity);
                String thumbprint = certificateUtils.getCertThumbprint(cert);
                byte[] pem = getPemBytes(Base64.getDecoder().decode(trustedPartyEntity.getRawData()));
                String filename = "CSCA/DCC/" + trustedPartyEntity.getCountry() + "/" + thumbprint + ".pem";
                addFile(zipOutputStream, filename, pem);
            });

            log.info("Generated Publication Archive with {} CSCA and {} DSC certificates",
                cscaTrustedParties.size(), signerInformationList.size());

            zipOutputStream.finish();

            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            log.error("Failed to create ZIP Archive.");
            log.debug("Failed to create ZIP Archive.", e);
            return null;
        }
    }

    private byte[] calculateSignature(byte[] zip) {
        log.debug("Signing created zip archive");
        PrivateKey privateKey;
        X509CertificateHolder signingCertificate;

        try {
            privateKey = (PrivateKey) publicationKeyStore.getKey(
                properties.getPublication().getCertificateAlias(),
                properties.getPublication().getKeyStorePass().toCharArray()
            );

            signingCertificate = certificateUtils.convertCertificate(
                (X509Certificate) publicationKeyStore.getCertificate(
                    properties.getPublication().getCertificateAlias()));
        } catch (Exception e) {
            log.error("Failed to load Publication Signing KeyPair from KeyStore: {}", e.getClass().getName());
            log.debug("Failed to load Publication Signing KeyPair from KeyStore", e);
            return null;
        }

        return Base64.getEncoder().encode(new SignedByteArrayMessageBuilder()
            .withPayload(zip)
            .withSigningCertificate(signingCertificate, privateKey)
            .build(true));
    }

    private void uploadGatewayData(byte[] zip, byte[] signature) {
        // TODO: Implement Upload
    }

    private byte[] getVersionFileContent() {
        String fileContent =
            "DCCG Data Export" + LINE_SEPERATOR + LINE_SEPERATOR
                + "Export Version: " + Instant.now().getEpochSecond() + LINE_SEPERATOR;
        return fileContent.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] getClasspathFileContent(String filename) {
        log.debug("Reading file {} from classpath", filename);
        File file;
        try {
            file = ResourceUtils.getFile("classpath:publication/" + filename);
        } catch (IOException e) {
            log.error("Failed to get file {} from classpath.", filename);
            log.debug("Failed to get file {} from classpath.", filename, e);
            return new byte[0];
        }

        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            return fileInputStream.readAllBytes();
        } catch (IOException e) {
            log.error("Failed to read content from file {} from classpath", filename);
            log.debug("Failed to read content from file {} from classpath.", filename, e);
            return new byte[0];
        }
    }

    private void addDirectory(ZipOutputStream zipOutputStream, String directory) {
        log.debug("Adding directory {} to publication archive", directory);
        try {
            zipOutputStream.putNextEntry(new ZipEntry(directory));
            zipOutputStream.closeEntry();
        } catch (IOException e) {
            log.error("Failed to add directory {} to publication archive.", directory);
        }
    }

    private void addFile(ZipOutputStream zipOutputStream, String filename, byte[] bytes) {
        log.debug("Adding file {} ({} Bytes) to publication archive", filename, bytes.length);
        try {
            zipOutputStream.putNextEntry(new ZipEntry(filename));
            zipOutputStream.write(bytes);
            zipOutputStream.closeEntry();
        } catch (IOException e) {
            log.error("Failed to add file {} to publication archive.", filename);
        }
    }

    private byte[] getPemBytes(byte[] certRawData) {
        String pem = PEM_BEGIN + LINE_SEPERATOR;
        pem += Base64.getMimeEncoder(64, LINE_SEPERATOR.getBytes(StandardCharsets.UTF_8))
            .encodeToString(certRawData);
        pem += LINE_SEPERATOR + PEM_END + LINE_SEPERATOR;

        return pem.getBytes(StandardCharsets.UTF_8);
    }

}
