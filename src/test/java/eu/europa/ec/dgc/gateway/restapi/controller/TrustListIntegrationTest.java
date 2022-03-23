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

package eu.europa.ec.dgc.gateway.restapi.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.repository.TrustedIssuerRepository;
import eu.europa.ec.dgc.gateway.repository.TrustedPartyRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustListDto;
import eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.gateway.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.gateway.testdata.SignerInformationTestHelper;
import eu.europa.ec.dgc.gateway.testdata.TrustedIssuerTestHelper;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.UnsupportedEncodingException;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import static org.hamcrest.Matchers.hasSize;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class TrustListIntegrationTest {

    @Autowired
    SignerInformationRepository signerInformationRepository;

    @Autowired
    TrustedPartyRepository trustedPartyRepository;

    @Autowired
    TrustedIssuerRepository trustedIssuerRepository;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    SignerInformationTestHelper signerInformationTestHelper;

    @Autowired
    TrustedIssuerTestHelper trustedIssuerTestHelper;

    @Autowired
    DgcConfigProperties dgcConfigProperties;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore dgcTestKeyStore;

    @Autowired
    private MockMvc mockMvc;

    private static final String countryCode = "EU";
    private static final String authCertSubject = "C=" + countryCode;
    private static final String IF_MODIFIED_SINCE_HEADER = "If-Modified-Since";
    private static final ZoneId gmt = ZoneId.of("GMT");
    private static final ZonedDateTime now = ZonedDateTime.now(gmt);
    private static final ZonedDateTime nowMinusOneMinute = ZonedDateTime.now(gmt).minusMinutes(1);
    private static final ZonedDateTime nowMinusOneHour = ZonedDateTime.now(gmt).minusHours(1);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz");
    private static final String nowMinusOneMinuteStr = formatter.format(nowMinusOneMinute);
    private static final String nowMinusOneHourStr = formatter.format(nowMinusOneHour);

    X509Certificate certUploadDe, certUploadEu, certCscaDe, certCscaEu, certAuthDe, certAuthEu, certDscDe, certDscEu,
        certUploadDe2, certUploadEu2, certCscaDe2, certCscaEu2, certAuthDe2, certAuthEu2, certDscDe2, certDscEu2, certDscEuDeleted;

    @BeforeEach
    void testData() throws Exception {
        trustedIssuerRepository.deleteAll();
        trustedPartyRepository.deleteAll();
        signerInformationRepository.deleteAll();

        certUploadDe = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "DE");
        certUploadEu = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "EU");
        certCscaDe = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "DE");
        certCscaEu = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "EU");
        certAuthDe = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.AUTHENTICATION, "DE");
        certAuthEu = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.AUTHENTICATION, "EU");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ec");
        certDscDe = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "DE", "Test");
        certDscEu = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "EU", "Test");

        signerInformationTestHelper.createSignerInformationInDB("DE", "sig1", certDscDe, now);
        signerInformationTestHelper.createSignerInformationInDB("EU", "sig2", certDscEu, now);

        trustedIssuerRepository.saveAll(List.of(
            trustedIssuerTestHelper.createTrustedIssuer("EU"),
            trustedIssuerTestHelper.createTrustedIssuer("DE"),
            trustedIssuerTestHelper.createTrustedIssuer("AT")
        ));
    }

    @Test
    void testTrustListDownloadNoFilterIsSince() throws Exception {
        prepareTestCertsCreatedAtNowMinusOneHour();
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/trustList")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(IF_MODIFIED_SINCE_HEADER, nowMinusOneHourStr)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certDscDe, "DE", CertificateTypeDto.DSC, "sig1"))
            .andExpect(c -> assertTrustListItem(c, certDscEu, "EU", CertificateTypeDto.DSC, "sig2"))
            .andExpect(c -> assertTrustListItem(c, certDscDe2, "DE", CertificateTypeDto.DSC, "sig3"))
            .andExpect(c -> assertTrustListItem(c, certDscEu2, "EU", CertificateTypeDto.DSC, "sig4"))
            .andExpect(c -> assertTrustListItem(c, certDscEuDeleted, "EU", CertificateTypeDto.DSC, null, true))
            .andExpect(c -> assertTrustListItem(c, certCscaDe, "DE", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certCscaEu, "EU", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certUploadDe, "DE", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certUploadEu, "EU", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certAuthDe, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthEu, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certCscaDe2, "DE", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certCscaEu2, "EU", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certUploadDe2, "DE", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certUploadEu2, "EU", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certAuthDe2, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthEu2, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 17));

        mockMvc.perform(get("/trustList")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(IF_MODIFIED_SINCE_HEADER, nowMinusOneMinuteStr)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListLength(c, 8));
    }
    @Test
    void testTrustListDownloadNoFilterPageable() throws Exception {
        prepareTestCertsCreatedAtNowMinusOneHour();
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/trustList?page=0&pagesize=100")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certDscDe, "DE", CertificateTypeDto.DSC, "sig1"))
            .andExpect(c -> assertTrustListItem(c, certDscEu, "EU", CertificateTypeDto.DSC, "sig2"))
            .andExpect(c -> assertTrustListItem(c, certDscDe2, "DE", CertificateTypeDto.DSC, "sig3"))
            .andExpect(c -> assertTrustListItem(c, certDscEu2, "EU", CertificateTypeDto.DSC, "sig4"))
            .andExpect(c -> assertTrustListItem(c, certDscEuDeleted, "EU", CertificateTypeDto.DSC, null, true))
            .andExpect(c -> assertTrustListItem(c, certCscaDe, "DE", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certCscaEu, "EU", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certUploadDe, "DE", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certUploadEu, "EU", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certAuthDe, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthEu, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certCscaDe2, "DE", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certCscaEu2, "EU", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certUploadDe2, "DE", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certUploadEu2, "EU", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certAuthDe2, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthEu2, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 17));
    }

    @Test
    void testTrustListDownloadNoFilterIsSincePageable() throws Exception {
        prepareTestCertsCreatedAtNowMinusOneHour();
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/trustList?page=-1&pagesize=10")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(IF_MODIFIED_SINCE_HEADER, nowMinusOneHourStr)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListLength(c, 17));

        mockMvc.perform(get("/trustList?page=0&pagesize=10")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(IF_MODIFIED_SINCE_HEADER, nowMinusOneHourStr)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListLength(c, 10));

        mockMvc.perform(get("/trustList?page=0&pagesize=100")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(IF_MODIFIED_SINCE_HEADER, nowMinusOneMinuteStr)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListLength(c, 8));

        mockMvc.perform(get("/trustList?page=1&pagesize=5")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(IF_MODIFIED_SINCE_HEADER, nowMinusOneMinuteStr)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListLength(c, 3));

        mockMvc.perform(get("/trustList?page=2&pagesize=10")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(IF_MODIFIED_SINCE_HEADER, nowMinusOneMinuteStr)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListLength(c, 0));
    }

    @Test
    void testTrustListDownloadNoFilterByTypeAndCountryIsSincePageable() throws Exception {
        prepareTestCertsCreatedAtNowMinusOneHour();
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/trustList/AUTHENTICATION")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(IF_MODIFIED_SINCE_HEADER, nowMinusOneHourStr)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certAuthDe, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthEu, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthDe2, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthEu2, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 4));

        mockMvc.perform(get("/trustList/AUTHENTICATION/DE")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certAuthDe, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthDe2, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 2));

        mockMvc.perform(get("/trustList/DSC?page=0&pagesize=10")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(IF_MODIFIED_SINCE_HEADER, nowMinusOneMinuteStr)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListLength(c, 2));

        mockMvc.perform(get("/trustList/DSC/DE?page=0&pagesize=10")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(IF_MODIFIED_SINCE_HEADER, nowMinusOneMinuteStr)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListLength(c, 1));
    }

    @Test
    void testTrustListDownloadNoFilter() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/trustList")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certDscDe, "DE", CertificateTypeDto.DSC, "sig1"))
            .andExpect(c -> assertTrustListItem(c, certDscEu, "EU", CertificateTypeDto.DSC, "sig2"))
            .andExpect(c -> assertTrustListItem(c, certCscaDe, "DE", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certCscaEu, "EU", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certUploadDe, "DE", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certUploadEu, "EU", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certAuthDe, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthEu, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 8));
    }

    @Test
    void testTrustListDownloadFilterByType() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/trustList/AUTHENTICATION")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certAuthDe, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthEu, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 2));

        mockMvc.perform(get("/trustList/UPLOAD")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certUploadDe, "DE", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certUploadEu, "EU", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListLength(c, 2));

        mockMvc.perform(get("/trustList/CSCA")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certCscaDe, "DE", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certCscaEu, "EU", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListLength(c, 2));

        mockMvc.perform(get("/trustList/DSC")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certDscDe, "DE", CertificateTypeDto.DSC, "sig1"))
            .andExpect(c -> assertTrustListItem(c, certDscEu, "EU", CertificateTypeDto.DSC, "sig2"))
            .andExpect(c -> assertTrustListLength(c, 2));
    }

    @Test
    void testTrustListDownloadFilterByTypeCaseInsensitive() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/trustList/aUtHeNtiCaTiOn")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certAuthDe, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListItem(c, certAuthEu, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 2));

        mockMvc.perform(get("/trustList/uploAd")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certUploadDe, "DE", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListItem(c, certUploadEu, "EU", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListLength(c, 2));

        mockMvc.perform(get("/trustList/csCA")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certCscaDe, "DE", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListItem(c, certCscaEu, "EU", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListLength(c, 2));

        mockMvc.perform(get("/trustList/dsc")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certDscDe, "DE", CertificateTypeDto.DSC, "sig1"))
            .andExpect(c -> assertTrustListItem(c, certDscEu, "EU", CertificateTypeDto.DSC, "sig2"))
            .andExpect(c -> assertTrustListLength(c, 2));
    }

    @Test
    void testTrustListDownloadFilterByTypeAndCountry() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/trustList/AUTHENTICATION/DE")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certAuthDe, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/AUTHENTICATION/EU")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certAuthEu, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/UPLOAD/DE")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certUploadDe, "DE", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/UPLOAD/EU")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certUploadEu, "EU", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/CSCA/DE")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certCscaDe, "DE", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/CSCA/EU")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certCscaEu, "EU", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/DSC/DE")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certDscDe, "DE", CertificateTypeDto.DSC, "sig1"))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/DSC/EU")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certDscEu, "EU", CertificateTypeDto.DSC, "sig2"))
            .andExpect(c -> assertTrustListLength(c, 1));
    }

    @Test
    void testTrustListDownloadFilterByTypeAndCountryLowercase() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/trustList/AUTHENTICATION/de")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certAuthDe, "DE", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/AUTHENTICATION/eu")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certAuthEu, "EU", CertificateTypeDto.AUTHENTICATION, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/UPLOAD/de")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certUploadDe, "DE", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/UPLOAD/eu")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certUploadEu, "EU", CertificateTypeDto.UPLOAD, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/CSCA/de")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certCscaDe, "DE", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/CSCA/eu")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certCscaEu, "EU", CertificateTypeDto.CSCA, null))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/DSC/de")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certDscDe, "DE", CertificateTypeDto.DSC, "sig1"))
            .andExpect(c -> assertTrustListLength(c, 1));

        mockMvc.perform(get("/trustList/DSC/eu")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(c -> assertTrustListItem(c, certDscEu, "EU", CertificateTypeDto.DSC, "sig2"))
            .andExpect(c -> assertTrustListLength(c, 1));
    }

    @Test
    void testTrustListDownloadEmptyList() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        signerInformationRepository.deleteAll();

        mockMvc.perform(get("/trustList/DSC")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(content().json("[]"));
    }

    @Test
    void testTrustedIssuerNoFilter() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        mockMvc.perform(get("/trustList/issuers")
                        .accept(MediaType.APPLICATION_JSON_VALUE)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(3)));
    }

    @Test
    void testTrustedIssuerByCountry() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        mockMvc.perform(get("/trustList/issuers?country=DE")
                        .accept(MediaType.APPLICATION_JSON_VALUE)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(1)));
    }

    @Test
    void testTrustedIssuerByMultipleCountries() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        mockMvc.perform(get("/trustList/issuers?country=DE,EU")
                        .accept(MediaType.APPLICATION_JSON_VALUE)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(2)));
    }

    @Test
    void testTrustedIssuerEmpty() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        mockMvc.perform(get("/trustList/issuers?country=XX")
                        .accept(MediaType.APPLICATION_JSON_VALUE)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/trustList/XXX",
            "/trustList/DSC/XXX",
            "/trustList/issuers?country=DE,XXX"
    })
    void testBadRequests(String url) throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        mockMvc.perform(get(url)
                        .accept(MediaType.APPLICATION_JSON_VALUE)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isBadRequest());
    }

    private void prepareTestCertsCreatedAtNowMinusOneHour() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ec");
        certDscDe2 = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(),
                "DE", "DETest");
        certDscEu2 = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(),
                "EU", "EUTest");
        certDscEuDeleted = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(),
                "EU", "EUTestDeleted");
        signerInformationTestHelper.createSignerInformationInDB("DE", "sig3", certDscDe2, nowMinusOneHour);
        signerInformationTestHelper.createSignerInformationInDB("EU", "sig4",certDscEu2, nowMinusOneHour);
        signerInformationTestHelper.createSignerInformationInDB("EU", "sig5_deleted",certDscEuDeleted, now.minusHours(2), nowMinusOneHour);

        certUploadDe2 = trustedPartyTestHelper.getTestCert("test1", TrustedPartyEntity.CertificateType.UPLOAD, "DE", nowMinusOneHour);
        certCscaDe2 = trustedPartyTestHelper.getTestCert("test2", TrustedPartyEntity.CertificateType.CSCA, "DE", nowMinusOneHour);
        certAuthDe2 = trustedPartyTestHelper.getTestCert("test3", TrustedPartyEntity.CertificateType.AUTHENTICATION, "DE", nowMinusOneHour);
        certUploadEu2 = trustedPartyTestHelper.getTestCert("test4", TrustedPartyEntity.CertificateType.UPLOAD, "EU", nowMinusOneHour);
        certCscaEu2 = trustedPartyTestHelper.getTestCert("test5", TrustedPartyEntity.CertificateType.CSCA, "EU", nowMinusOneHour);
        certAuthEu2 = trustedPartyTestHelper.getTestCert("test6", TrustedPartyEntity.CertificateType.AUTHENTICATION, "EU", nowMinusOneHour);
    }

    private void assertTrustListItem(MvcResult result, X509Certificate certificate, String country, CertificateTypeDto certificateTypeDto, String signature) throws UnsupportedEncodingException, CertificateEncodingException, JsonProcessingException {
        assertTrustListItem(result, certificate, country, certificateTypeDto, signature, false);
    }

    private void assertTrustListItem(MvcResult result, X509Certificate certificate, String country, CertificateTypeDto certificateTypeDto, String signature, boolean deleted) throws CertificateEncodingException, UnsupportedEncodingException, JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());
        List<TrustListDto> trustList = objectMapper.readValue(result.getResponse().getContentAsString(), new TypeReference<>() {
        });

        Optional<TrustListDto> trustListOptional = trustList
            .stream()
            .filter(tl -> tl.getKid().equals(certificateUtils.getCertKid(certificate)))
            .findFirst();

        Assertions.assertTrue(trustListOptional.isPresent());

        TrustListDto trustListItem = trustListOptional.get();

        Assertions.assertEquals(certificateUtils.getCertKid(certificate), trustListItem.getKid());
        Assertions.assertEquals(country, trustListItem.getCountry());
        Assertions.assertEquals(certificateTypeDto, trustListItem.getCertificateType());
        Assertions.assertEquals(certificateUtils.getCertThumbprint(certificate), trustListItem.getThumbprint());
        if (deleted) {
            Assertions.assertNull(trustListItem.getRawData());
        } else {
            Assertions.assertEquals(Base64.getEncoder().encodeToString(certificate.getEncoded()), trustListItem.getRawData());
        }
        if (signature != null) {
            Assertions.assertEquals(signature, trustListItem.getSignature());
        }
    }

    private void assertTrustListLength(MvcResult result, int expectedLength) throws UnsupportedEncodingException, JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());
        List<TrustListDto> trustList = objectMapper.readValue(result.getResponse().getContentAsString(), new TypeReference<>() {
        });
        Assertions.assertEquals(expectedLength, trustList.size());
    }
}
