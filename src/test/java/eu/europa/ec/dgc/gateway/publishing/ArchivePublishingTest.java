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

package eu.europa.ec.dgc.gateway.publishing;

import eu.europa.ec.dgc.gateway.client.AssetManagerClient;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.model.AssetManagerSynchronizeResponseDto;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.repository.TrustedPartyRepository;
import eu.europa.ec.dgc.gateway.service.PublishingService;
import eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.gateway.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.gateway.testdata.SignerInformationTestHelper;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.signing.SignedByteArrayMessageParser;
import eu.europa.ec.dgc.signing.SignedMessageParser;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.Mockito;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;
import org.springframework.util.ResourceUtils;

@SpringBootTest(properties = {
        "dgc.publication.enabled=true",
        "dgc.publication.synchronizeEnabled=true",
        "dgc.publication.downloadEnabled=true",
        "dgc.publication.user=user",
        "dgc.publication.password=pass",
        "dgc.publication.amngruid=uid",
        "dgc.publication.path=path/a/b",
        "dgc.publication.archiveFilename=db.zip",
        "dgc.publication.signatureFilename=db.zip.sig.txt",
        "dgc.publication.notifyEmails[0]=u1@c1.de",
        "dgc.publication.notifyEmails[1]=u1@c2.de"
})
@Slf4j
public class ArchivePublishingTest {

    @MockBean
    AssetManagerClient assetManagerClientMock;

    @Autowired
    TrustedPartyRepository trustedPartyRepository;

    @Autowired
    SignerInformationRepository signerInformationRepository;

    @Autowired
    PublishingService publishingService;

    @Autowired
    AssetManagerClient assetManagerClient;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    SignerInformationTestHelper signerInformationTestHelper;

    @Autowired
    DgcTestKeyStore dgcTestKeyStore;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcConfigProperties properties;

    @TempDir
    File tempDir;

    private static final String expectedAuthHeader =
            "Basic " + Base64.getEncoder().encodeToString("user:pass".getBytes(StandardCharsets.UTF_8));
    private static final String expectedUid = "uid";
    private static final String expectedPath = "path/a/b";
    private static final String expectedArchiveName = "db.zip";
    private static final String expectedSignatureName = "db.zip.sig.txt";

    private X509Certificate csca1, csca2, csca3, csca4;
    private X509Certificate dsc1, dsc2, dsc3, dsc4;

    @BeforeEach
    public void setup() throws Exception {
        properties.getPublication().setDownloadPath(tempDir.getAbsolutePath());

        trustedPartyRepository.deleteAll();
        signerInformationRepository.deleteAll();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ec");

        csca1 = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "C1");
        csca2 = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "C2");
        csca3 = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "C3");
        csca4 = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "C4");

        dsc1 = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "C1",
            "DSC C1", csca1, trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, "C1"));
        dsc2 = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "C2",
            "DSC C2", csca2, trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, "C2"));
        dsc3 = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "C3",
            "DSC C3", csca3, trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, "C3"));
        dsc4 = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "C4",
            "DSC C4", csca4, trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, "C4"));

        signerInformationTestHelper.createSignerInformationInDB("C1", "XXX", dsc1, ZonedDateTime.now());
        signerInformationTestHelper.createSignerInformationInDB("C2", "XXX", dsc2, ZonedDateTime.now());
        signerInformationTestHelper.createSignerInformationInDB("C3", "XXX", dsc3, ZonedDateTime.now());
        signerInformationTestHelper.createSignerInformationInDB("C4", "XXX", dsc4, ZonedDateTime.now());
    }

    @Test
    public void testArchiveContainsRequiredFiles() throws Exception {

        ArgumentCaptor<byte[]> uploadArchiveArgumentCaptor = ArgumentCaptor.forClass(byte[].class);
        ArgumentCaptor<byte[]> uploadSignatureArgumentCaptor = ArgumentCaptor.forClass(byte[].class);
        ArgumentCaptor<AssetManagerClient.SynchronizeFormData> synchronizeFormDataArgumentCaptor = ArgumentCaptor.forClass(AssetManagerClient.SynchronizeFormData.class);
        byte[] dummyByteArrayArchive = new byte[]{0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf};
        byte[] dummyByteArraySignature = new byte[]{0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa};

        when(assetManagerClientMock.uploadFile(eq(expectedAuthHeader), eq(expectedUid), eq(expectedPath), eq(expectedArchiveName), uploadArchiveArgumentCaptor.capture()))
                .thenReturn(ResponseEntity.ok(null));

        when(assetManagerClientMock.uploadFile(eq(expectedAuthHeader), eq(expectedUid), eq(expectedPath), eq(expectedSignatureName), uploadSignatureArgumentCaptor.capture()))
                .thenReturn(ResponseEntity.ok(null));

        when(assetManagerClientMock.synchronize(eq(expectedAuthHeader), eq("true"), synchronizeFormDataArgumentCaptor.capture()))
                .thenReturn(ResponseEntity.ok(new AssetManagerSynchronizeResponseDto("OK", 200, "Message", expectedPath, "token")));

        when(assetManagerClientMock.downloadFile(expectedAuthHeader, expectedUid, expectedPath, expectedArchiveName))
                .thenReturn(ResponseEntity.ok(dummyByteArrayArchive));

        when(assetManagerClientMock.downloadFile(expectedAuthHeader, expectedUid, expectedPath, expectedSignatureName))
                .thenReturn(ResponseEntity.ok(dummyByteArraySignature));

        publishingService.publishGatewayData();

        verify(assetManagerClientMock).uploadFile(eq(expectedAuthHeader), eq(expectedUid), eq(expectedPath), eq(expectedArchiveName), any());
        verify(assetManagerClientMock).uploadFile(eq(expectedAuthHeader), eq(expectedUid), eq(expectedPath), eq(expectedSignatureName), any());
        verify(assetManagerClientMock).synchronize(eq(expectedAuthHeader), eq("true"), any());
        verify(assetManagerClientMock).downloadFile(expectedAuthHeader, expectedUid, expectedPath, expectedArchiveName);
        verify(assetManagerClientMock).downloadFile(expectedAuthHeader, expectedUid, expectedPath, expectedSignatureName);

        Assertions.assertNotNull(uploadArchiveArgumentCaptor.getValue());
        Assertions.assertNotNull(uploadSignatureArgumentCaptor.getValue());
        Assertions.assertNotNull(synchronizeFormDataArgumentCaptor.getValue());

        Assertions.assertEquals(expectedPath, synchronizeFormDataArgumentCaptor.getValue().getPath());
        Assertions.assertArrayEquals(new String[]{expectedArchiveName, expectedSignatureName}, synchronizeFormDataArgumentCaptor.getValue().getNodeList().split(","));
        Assertions.assertArrayEquals(new String[]{"u1@c1.de", "u1@c2.de"}, synchronizeFormDataArgumentCaptor.getValue().getNotifyEmails().split(","));


        Map<String, byte[]> archiveContent = readZipFile(uploadArchiveArgumentCaptor.getValue());
        Assertions.assertEquals(11, archiveContent.size());

        /*
         * Check for Static files.
         */
        Assertions.assertTrue(archiveContent.containsKey("Readme.txt"));
        Assertions.assertArrayEquals(FileUtils.readFileToByteArray(ResourceUtils.getFile("classpath:publication/Readme.txt")), archiveContent.get("Readme.txt"));

        Assertions.assertTrue(archiveContent.containsKey("License.txt"));
        Assertions.assertArrayEquals(FileUtils.readFileToByteArray(ResourceUtils.getFile("classpath:publication/License.txt")), archiveContent.get("License.txt"));

        /*
         * Check for Version file
         */
        Assertions.assertTrue(archiveContent.containsKey("Version.txt"));
        String versionFileContent = new String(archiveContent.get("Version.txt"), StandardCharsets.UTF_8);
        ZonedDateTime parsedTimestamp = ZonedDateTime.parse(versionFileContent.substring(versionFileContent.indexOf(":") + 2).trim(), DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        Assertions.assertTrue(ZonedDateTime.now().until(parsedTimestamp, ChronoUnit.SECONDS) < 10);

        /*
         * Check for CSCA
         */
        Assertions.assertTrue((archiveContent.containsKey("CSCA/DCC/C1/" + certificateUtils.getCertThumbprint(csca1) + ".pem")));
        checkPemFile(csca1, archiveContent.get("CSCA/DCC/C1/" + certificateUtils.getCertThumbprint(csca1) + ".pem"));

        Assertions.assertTrue((archiveContent.containsKey("CSCA/DCC/C2/" + certificateUtils.getCertThumbprint(csca2) + ".pem")));
        checkPemFile(csca2, archiveContent.get("CSCA/DCC/C2/" + certificateUtils.getCertThumbprint(csca2) + ".pem"));

        Assertions.assertTrue((archiveContent.containsKey("CSCA/DCC/C3/" + certificateUtils.getCertThumbprint(csca3) + ".pem")));
        checkPemFile(csca3, archiveContent.get("CSCA/DCC/C3/" + certificateUtils.getCertThumbprint(csca3) + ".pem"));

        Assertions.assertTrue((archiveContent.containsKey("CSCA/DCC/C4/" + certificateUtils.getCertThumbprint(csca4) + ".pem")));
        checkPemFile(csca4, archiveContent.get("CSCA/DCC/C4/" + certificateUtils.getCertThumbprint(csca4) + ".pem"));

        /*
         * Check for DSC
         */
        Assertions.assertTrue((archiveContent.containsKey("DSC/DCC/C1/" + certificateUtils.getCertThumbprint(dsc1) + ".pem")));
        checkPemFile(dsc1, archiveContent.get("DSC/DCC/C1/" + certificateUtils.getCertThumbprint(dsc1) + ".pem"));

        Assertions.assertTrue((archiveContent.containsKey("DSC/DCC/C2/" + certificateUtils.getCertThumbprint(dsc2) + ".pem")));
        checkPemFile(dsc2, archiveContent.get("DSC/DCC/C2/" + certificateUtils.getCertThumbprint(dsc2) + ".pem"));

        Assertions.assertTrue((archiveContent.containsKey("DSC/DCC/C3/" + certificateUtils.getCertThumbprint(dsc3) + ".pem")));
        checkPemFile(dsc3, archiveContent.get("DSC/DCC/C3/" + certificateUtils.getCertThumbprint(dsc3) + ".pem"));

        Assertions.assertTrue((archiveContent.containsKey("DSC/DCC/C4/" + certificateUtils.getCertThumbprint(dsc4) + ".pem")));
        checkPemFile(dsc4, archiveContent.get("DSC/DCC/C4/" + certificateUtils.getCertThumbprint(dsc4) + ".pem"));

        /*
         * Check Signature
         */
        SignedByteArrayMessageParser parser = new SignedByteArrayMessageParser(uploadSignatureArgumentCaptor.getValue(), Base64.getEncoder().encode(uploadArchiveArgumentCaptor.getValue()));
        Assertions.assertEquals(SignedMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertArrayEquals(dgcTestKeyStore.getPublicationSigner().getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());

        /*
         * Check Downloaded files
         */
        byte[] downloadedArchiveFile = FileUtils.readFileToByteArray(
                Paths.get(tempDir.getAbsolutePath(), properties.getPublication().getArchiveFilename()).toFile());
        Assertions.assertArrayEquals(dummyByteArrayArchive, downloadedArchiveFile);

        byte[] downloadedSignatureFile = FileUtils.readFileToByteArray(
                Paths.get(tempDir.getAbsolutePath(), properties.getPublication().getSignatureFilename()).toFile());
        Assertions.assertArrayEquals(dummyByteArraySignature, downloadedSignatureFile);
    }

    @Test
    public void testSynchronizeDisabled() {

        when(assetManagerClientMock.uploadFile(eq(expectedAuthHeader), eq(expectedUid), eq(expectedPath), eq(expectedArchiveName), any()))
                .thenReturn(ResponseEntity.ok(null));

        when(assetManagerClientMock.uploadFile(eq(expectedAuthHeader), eq(expectedUid), eq(expectedPath), eq(expectedSignatureName), any()))
                .thenReturn(ResponseEntity.ok(null));

        when(assetManagerClientMock.downloadFile(expectedAuthHeader, expectedUid, expectedPath, expectedArchiveName))
                .thenReturn(ResponseEntity.ok(new byte[]{}));

        when(assetManagerClientMock.downloadFile(expectedAuthHeader, expectedUid, expectedPath, expectedSignatureName))
                .thenReturn(ResponseEntity.ok(new byte[]{}));

        properties.getPublication().setSynchronizeEnabled(false);

        publishingService.publishGatewayData();

        properties.getPublication().setSynchronizeEnabled(true);

        verify(assetManagerClientMock).uploadFile(eq(expectedAuthHeader), eq(expectedUid), eq(expectedPath), eq(expectedArchiveName), any());
        verify(assetManagerClientMock).uploadFile(eq(expectedAuthHeader), eq(expectedUid), eq(expectedPath), eq(expectedSignatureName), any());
        verify(assetManagerClientMock, Mockito.never()).synchronize(eq(expectedAuthHeader), eq("true"), any());
    }

    private void checkPemFile(X509Certificate expected, byte[] pemFile) throws IOException, CertificateEncodingException {
        try (
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pemFile);
            InputStreamReader inputStreamReader = new InputStreamReader(byteArrayInputStream);
            PEMParser pemParser = new PEMParser(inputStreamReader)
        ) {
            Object object = pemParser.readObject();
            Assertions.assertTrue(object instanceof X509CertificateHolder);

            X509CertificateHolder cert = (X509CertificateHolder) object;
            Assertions.assertArrayEquals(expected.getEncoded(), cert.getEncoded());
        }
    }

    private Map<String, byte[]> readZipFile(byte[] zipFile) throws IOException {
        Map<String, byte[]> fileMap = new HashMap<>();

        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(zipFile);
             ZipInputStream zipInputStream = new ZipInputStream(byteArrayInputStream)) {

            ZipEntry zipEntry;
            while ((zipEntry = zipInputStream.getNextEntry()) != null) {
                if (!zipEntry.isDirectory()) {
                    fileMap.put(zipEntry.getName(), zipInputStream.readAllBytes());
                }
            }
        }

        return fileMap;
    }

}
