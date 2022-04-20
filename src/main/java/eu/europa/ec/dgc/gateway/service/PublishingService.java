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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.client.AssetManagerClient;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.model.AssetManagerSynchronizeResponseDto;
import eu.europa.ec.dgc.signing.SignedByteArrayMessageBuilder;
import eu.europa.ec.dgc.utils.CertificateUtils;
import feign.FeignException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

@Service
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty("dgc.publication.enabled")
public class PublishingService {

    private final TrustedPartyService trustedPartyService;

    private final SignerInformationService signerInformationService;

    private final CertificateUtils certificateUtils;

    private final DgcConfigProperties properties;

    private final AssetManagerClient assetManagerClient;

    private final ObjectMapper objectMapper;

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

        if (properties.getPublication().getDownloadEnabled()) {
            downloadFile(properties.getPublication().getArchiveFilename());
            downloadFile(properties.getPublication().getSignatureFilename());
        }

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
            addFileToZip(zipOutputStream, "Readme.txt", getClasspathFileContent("Readme.txt"));
            addFileToZip(zipOutputStream, "License.txt", getClasspathFileContent("License.txt"));
            addFileToZip(zipOutputStream, "Version.txt", getVersionFileContent());

            /*
             * Add DSC
             */
            addDirectoryToZip(zipOutputStream, "DSC/");
            addDirectoryToZip(zipOutputStream, "DSC/DCC/");
            signerInformationList.stream()
                .map(SignerInformationEntity::getCountry)
                .distinct()
                .forEach(country -> addDirectoryToZip(zipOutputStream, "DSC/DCC/" + country + "/"));

            signerInformationList.forEach(signerInformation -> {
                X509Certificate cert = signerInformationService.getX509CertificateFromEntity(signerInformation);
                String thumbprint = certificateUtils.getCertThumbprint(cert);
                byte[] pem = getPemBytes(Base64.getDecoder().decode(signerInformation.getRawData()));
                String filename = "DSC/DCC/" + signerInformation.getCountry() + "/" + thumbprint + ".pem";
                addFileToZip(zipOutputStream, filename, pem);
            });

            /*
             * Add CSCA
             */
            addDirectoryToZip(zipOutputStream, "CSCA/");
            addDirectoryToZip(zipOutputStream, "CSCA/DCC/");
            cscaTrustedParties.stream()
                .map(TrustedPartyEntity::getCountry)
                .distinct()
                .forEach(country -> addDirectoryToZip(zipOutputStream, "CSCA/DCC/" + country + "/"));

            cscaTrustedParties.forEach(trustedPartyEntity -> {
                X509Certificate cert = trustedPartyService.getX509CertificateFromEntity(trustedPartyEntity);
                String thumbprint = certificateUtils.getCertThumbprint(cert);
                byte[] pem = getPemBytes(Base64.getDecoder().decode(trustedPartyEntity.getRawData()));
                String filename = "CSCA/DCC/" + trustedPartyEntity.getCountry() + "/" + thumbprint + ".pem";
                addFileToZip(zipOutputStream, filename, pem);
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
                properties.getPublication().getKeystore().getCertificateAlias(),
                properties.getPublication().getKeystore().getKeyStorePass().toCharArray()
            );

            signingCertificate = certificateUtils.convertCertificate(
                (X509Certificate) publicationKeyStore.getCertificate(
                    properties.getPublication().getKeystore().getCertificateAlias()));
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
        String archiveFilename = properties.getPublication().getArchiveFilename();
        String signatureFilename = properties.getPublication().getSignatureFilename();

        log.info("Uploading DGCG Publication Archive: {}, {}", archiveFilename, signatureFilename);

        try {
            ResponseEntity<Void> zipUploadResponse = assetManagerClient.uploadFile(getAuthHeader(),
                properties.getPublication().getAmngrUid(), properties.getPublication().getPath(), archiveFilename, zip);

            if (zipUploadResponse.getStatusCode().is2xxSuccessful()) {
                log.info("Upload of ZIP Archive was successful.");
            } else {
                log.error("Failed to Upload ZIP Archive: {}", zipUploadResponse.getStatusCode());
                return;
            }
        } catch (FeignException.FeignServerException e) {
            log.error("Failed to Upload ZIP Archive: {}", e.status());
            return;
        }

        if (signature != null) {
            try {
                ResponseEntity<Void> signatureUploadResponse = assetManagerClient.uploadFile(getAuthHeader(),
                    properties.getPublication().getAmngrUid(), properties.getPublication().getPath(), signatureFilename,
                    signature);

                if (signatureUploadResponse.getStatusCode().is2xxSuccessful()) {
                    log.info("Upload of Signature file was successful.");
                } else {
                    log.error("Failed to Upload Signature file: {}", signatureUploadResponse.getStatusCode());
                    return;
                }
            } catch (FeignException.FeignServerException e) {
                log.error("Failed to Upload Signature file: {}", e.status());
                return;
            }
        } else {
            log.info("Skipping Upload of Signature because it could not be created.");
        }

        log.info("All files uploaded, start synchronize process");

        if (!properties.getPublication().getSynchronizeEnabled()) {
            log.info("Synchronizing Files is disabled.");
            return;
        }

        try {
            ResponseEntity<AssetManagerSynchronizeResponseDto> synchronizeResponse = assetManagerClient.synchronize(
                getAuthHeader(), "true",
                new AssetManagerClient.SynchronizeFormData(
                    properties.getPublication().getPath(),
                    String.join(",", archiveFilename, signatureFilename),
                    String.join(",", properties.getPublication().getNotifyEmails())));

            if (synchronizeResponse.getBody() != null && synchronizeResponse.getStatusCode().is2xxSuccessful()) {
                if (synchronizeResponse.getBody().getOcs().getData().getStatusCode() == 200
                    && synchronizeResponse.getBody().getOcs().getMeta().getStatuscode() == 200) {

                    log.info("Successfully triggered synchronization from acc to prd.");
                } else {
                    log.error("Failed to trigger synchronization from acc to prd: {}, {}, {}",
                        synchronizeResponse.getStatusCode(),
                        synchronizeResponse.getBody().getOcs().getData().getStatusMessage(),
                        synchronizeResponse.getBody().getOcs().getMeta().getMessage());
                }
            } else {
                log.error("Failed to trigger synchronization from acc to prd: {}, {}, {}",
                    synchronizeResponse.getStatusCode(), synchronizeResponse.getBody(),
                    objectMapper.writeValueAsString(synchronizeResponse.getBody()));
                return;
            }
        } catch (FeignException e) {
            log.error("Failed to trigger synchronization from acc to prd: {}", e.status());
            return;
        } catch (JsonProcessingException e) {
            log.error("Failed to trigger synchronization from acc to prd: {}", e.getMessage());
            return;
        }

        log.info("Upload and Synchronize successful");
    }

    private void downloadFile(String filename) {
        log.info("Downloading uploaded DGCG Publication File: {}", filename);

        ResponseEntity<byte[]> downloadResponse;
        try {
            downloadResponse = assetManagerClient.downloadFile(getAuthHeader(),
                    properties.getPublication().getAmngrUid(), properties.getPublication().getPath(), filename);

            if (downloadResponse.getStatusCode().is2xxSuccessful()) {
                log.info("Download of file {} was successful.", filename);
            } else {
                log.error("Failed to download file: {}", downloadResponse.getStatusCode());
            }
        } catch (FeignException.FeignServerException e) {
            log.error("Failed to Download file: {}", e.status());
            return;
        }

        File targetFile = Paths.get(properties.getPublication().getDownloadPath(), filename).toFile();

        try {
            Files.deleteIfExists(targetFile.toPath());
        } catch (IOException e) {
            log.error("Failed to delete existing file: {}, {}", targetFile.getAbsolutePath(), e.getMessage());
            return;
        }

        if (downloadResponse.hasBody() && downloadResponse.getBody() != null) {
            try (FileOutputStream fileOutputStream = new FileOutputStream(targetFile)) {
                fileOutputStream.write(downloadResponse.getBody());
                log.info("Saved file {} to {} ({} Bytes)",
                        filename, targetFile.getAbsolutePath(), downloadResponse.getBody().length);
            } catch (IOException e) {
                log.error("Failed to write downloaded file to disk: {}, {}",
                        targetFile.getAbsolutePath(), e.getMessage());
            }
        } else {
            log.error("Download Response does not contain any body");
        }

    }

    private String getAuthHeader() {
        String header = "Basic ";
        header += Base64.getEncoder().encodeToString((properties.getPublication().getUser() + ":"
                + properties.getPublication().getPassword()).getBytes(StandardCharsets.UTF_8));
        return header;
    }

    private byte[] getVersionFileContent() {
        String fileContent =
            "DGCG Data Export"
                + LINE_SEPERATOR + LINE_SEPERATOR
                + "Export Timestamp: "
                + ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                + LINE_SEPERATOR;

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

    private void addDirectoryToZip(ZipOutputStream zipOutputStream, String directory) {
        log.debug("Adding directory {} to publication archive", directory);
        try {
            zipOutputStream.putNextEntry(new ZipEntry(directory));
            zipOutputStream.closeEntry();
        } catch (IOException e) {
            log.error("Failed to add directory {} to publication archive.", directory);
        }
    }

    private void addFileToZip(ZipOutputStream zipOutputStream, String filename, byte[] bytes) {
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
