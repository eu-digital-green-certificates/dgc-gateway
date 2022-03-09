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

package eu.europa.ec.dgc.gateway.restapi.controller;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.ser.ZonedDateTimeSerializer;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedReferenceEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedReferenceRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDeleteRequestDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDto;
import eu.europa.ec.dgc.gateway.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatterBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class TrustedReferenceIntegrationTest {

    @Autowired
    TrustedReferenceRepository trustedReferenceRepository;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    DgcConfigProperties dgcConfigProperties;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore dgcTestKeyStore;

    @Autowired
    private MockMvc mockMvc;

    ObjectMapper objectMapper;

    private static final String countryCode = "EU";
    private static final String authCertSubject = "C=" + countryCode;

    @BeforeEach
    void setup() {
        trustedReferenceRepository.deleteAll();

        objectMapper = new ObjectMapper();

        JavaTimeModule javaTimeModule = new JavaTimeModule();
        javaTimeModule.addSerializer(ZonedDateTime.class, new ZonedDateTimeSerializer(
                new DateTimeFormatterBuilder().appendPattern("yyyy-MM-dd'T'HH:mm:ssXXX").toFormatter()
        ));

        objectMapper.registerModule(javaTimeModule);
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Test
    void testTrustedReferenceDownload() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        trustedReferenceRepository.save(createTrustedReference());
        mockMvc.perform(get("/trustList/references")
                        .accept(MediaType.APPLICATION_JSON_VALUE)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(1)));
    }

    @Test
    void testTrustedReferenceDelete() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        TrustedReferenceEntity entity = trustedReferenceRepository.save(createTrustedReference());
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        TrustedReferenceDeleteRequestDto deleteRequestDto = new TrustedReferenceDeleteRequestDto(entity.getUuid());
        String deletePayload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
                .buildAsString();
        mockMvc.perform(delete("/trust/reference")
                        .content(deletePayload)
                        .contentType("application/cms")
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                        .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
                )
                .andExpect(status().isNoContent());

        assertTrue(trustedReferenceRepository.findAll().isEmpty());
    }

    @Test
    void testTrustedReferenceWrongCountry() throws Exception {
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        TrustedReferenceDto trustedReferenceDto = createTrustedReferenceDto();
        trustedReferenceDto.setCountry("DE");

        String payload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(trustedReferenceDto))
                .buildAsString();

        mockMvc.perform(post("/trust/reference")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isForbidden());
        assertTrue(trustedReferenceRepository.findAll().isEmpty());
    }

    @Test
    void testTrustedReferenceDeleteWrongCountry() throws Exception {
        // Create TrustedReference with CountryCode 'countryCode'
        TrustedReferenceEntity entity = trustedReferenceRepository.save(createTrustedReference());

        // Deleting TrustedReference with auth of another country
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, "XX");
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX");
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        TrustedReferenceDeleteRequestDto deleteRequestDto = new TrustedReferenceDeleteRequestDto(entity.getUuid());
        String deletePayload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(deleteRequestDto))
            .buildAsString();
        mockMvc.perform(delete("/trust/reference")
                .content(deletePayload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), "C=XX")
            )
            .andExpect(status().isForbidden());

        assertFalse(trustedReferenceRepository.findAll().isEmpty());
    }

    private TrustedReferenceEntity createTrustedReference() {
        TrustedReferenceEntity trustedReference = new TrustedReferenceEntity();
        trustedReference.setReferenceVersion("1.0");
        trustedReference.setType(TrustedReferenceEntity.ReferenceType.DCC);
        trustedReference.setService("trustService");
        trustedReference.setName("trustName");
        trustedReference.setCountry(countryCode);
        trustedReference.setContentType("cms");
        trustedReference.setSignatureType(TrustedReferenceEntity.SignatureType.CMS);
        return trustedReference;
    }

    private TrustedReferenceDto createTrustedReferenceDto() {
        TrustedReferenceDto trustedReference = new TrustedReferenceDto();
        trustedReference.setReferenceVersion("1.0");
        trustedReference.setType(TrustedReferenceDto.ReferenceTypeDto.DCC);
        trustedReference.setService("trustService");
        trustedReference.setName("trustName");
        trustedReference.setCountry(countryCode);
        trustedReference.setContentType("cms");
        trustedReference.setSignatureType(TrustedReferenceDto.SignatureTypeDto.CMS);
        trustedReference.setSslPublicKey("pubKey");
        trustedReference.setThumbprint("thumbprint");
        trustedReference.setVersion(1L);
        return trustedReference;
    }
}
