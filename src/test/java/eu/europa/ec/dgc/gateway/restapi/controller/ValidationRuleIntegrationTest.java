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

import static eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils.assertEquals;
import static eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils.getDummyValidationRule;
import static java.time.format.DateTimeFormatter.ISO_LOCAL_DATE;
import static java.time.temporal.ChronoField.HOUR_OF_DAY;
import static java.time.temporal.ChronoField.MINUTE_OF_HOUR;
import static java.time.temporal.ChronoField.SECOND_OF_MINUTE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.ser.ZonedDateTimeSerializer;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.connector.model.ValidationRule;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.entity.ValidationRuleEntity;
import eu.europa.ec.dgc.gateway.repository.AuditEventRepository;
import eu.europa.ec.dgc.gateway.repository.ValidationRuleRepository;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.signing.SignedStringMessageParser;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@Slf4j
class ValidationRuleIntegrationTest {

    @Autowired
    DgcConfigProperties dgcConfigProperties;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    AuditEventRepository auditEventRepository;

    @Autowired
    ValidationRuleRepository validationRuleRepository;

    ObjectMapper objectMapper;

    @Autowired
    private MockMvc mockMvc;

    private static final DateTimeFormatter formatter = new DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(ISO_LOCAL_DATE)
        .appendLiteral('T')
        .appendValue(HOUR_OF_DAY, 2)
        .appendLiteral(':')
        .appendValue(MINUTE_OF_HOUR, 2)
        .optionalStart()
        .appendLiteral(':')
        .appendValue(SECOND_OF_MINUTE, 2)
        .appendOffsetId()
        .toFormatter();

    private static final String countryCode = "EU";
    private static final String authCertSubject = "C=" + countryCode;

    @BeforeEach
    public void setup() {
        validationRuleRepository.deleteAll();
        auditEventRepository.deleteAll();

        objectMapper = new ObjectMapper();

        JavaTimeModule javaTimeModule = new JavaTimeModule();
        javaTimeModule.addSerializer(ZonedDateTime.class, new ZonedDateTimeSerializer(
            new DateTimeFormatterBuilder().appendPattern("yyyy-MM-dd'T'HH:mm:ssXXX").toFormatter()
        ));

        objectMapper.registerModule(javaTimeModule);
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    }

    @Test
    void testSuccessfulUpload() throws Exception {
        long validationRulesInDb = validationRuleRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        Assertions.assertEquals(validationRulesInDb + 1, validationRuleRepository.count());
        Optional<ValidationRuleEntity> createdValidationRule =
            validationRuleRepository.getByRuleIdAndVersion(validationRule.getIdentifier(), validationRule.getVersion());

        Assertions.assertTrue(createdValidationRule.isPresent());

        Assertions.assertEquals(auditEventEntitiesInDb + 1, auditEventRepository.count());
        Assertions.assertEquals(validationRule.getValidFrom().toEpochSecond(), createdValidationRule.get().getValidFrom().toEpochSecond());
        Assertions.assertEquals(validationRule.getValidTo().toEpochSecond(), createdValidationRule.get().getValidTo().toEpochSecond());
        Assertions.assertEquals(validationRule.getCountry(), createdValidationRule.get().getCountry());
        Assertions.assertEquals(validationRule.getType().toUpperCase(Locale.ROOT), createdValidationRule.get().getValidationRuleType().toString());

        SignedStringMessageParser parser = new SignedStringMessageParser(createdValidationRule.get().getCms());
        ValidationRule parsedValidationRule = objectMapper.readValue(parser.getPayload(), ValidationRule.class);

        assertEquals(validationRule, parsedValidationRule);
    }

    @Test
    void testSuccessfulUploadWithoutRegionProperty() throws Exception {
        long validationRulesInDb = validationRuleRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        ValidationRule validationRule = getDummyValidationRule();
        validationRule.setRegion(null);
        String json = objectMapper.writeValueAsString(validationRule);
        json = json.replace("\"Region\":null,", "");

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(json)
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        Assertions.assertEquals(validationRulesInDb + 1, validationRuleRepository.count());
        Optional<ValidationRuleEntity> createdValidationRule =
            validationRuleRepository.getByRuleIdAndVersion(validationRule.getIdentifier(), validationRule.getVersion());

        Assertions.assertTrue(createdValidationRule.isPresent());

        Assertions.assertEquals(auditEventEntitiesInDb + 1, auditEventRepository.count());
        Assertions.assertEquals(validationRule.getValidFrom().toEpochSecond(), createdValidationRule.get().getValidFrom().toEpochSecond());
        Assertions.assertEquals(validationRule.getValidTo().toEpochSecond(), createdValidationRule.get().getValidTo().toEpochSecond());
        Assertions.assertEquals(validationRule.getCountry(), createdValidationRule.get().getCountry());
        Assertions.assertEquals(validationRule.getType().toUpperCase(Locale.ROOT), createdValidationRule.get().getValidationRuleType().toString());

        SignedStringMessageParser parser = new SignedStringMessageParser(createdValidationRule.get().getCms());
        ValidationRule parsedValidationRule = objectMapper.readValue(parser.getPayload(), ValidationRule.class);

        assertEquals(validationRule, parsedValidationRule);
    }

    @Test
    void testInputOnlyContainsJson() throws Exception {
        long validationRulesInDb = validationRuleRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule) + "\n" + objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/rules")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule) + "x")
            .buildAsString();

        authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/rules")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(validationRulesInDb, validationRuleRepository.count());
    }

    @Test
    void testJsonSchemaValidation() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        Map<String, ValidationRule> invalidValidationRules = new HashMap<>();

        ValidationRule validationRule = getDummyValidationRule();
        validationRule.setIdentifier("XXXXXXXX");
        invalidValidationRules.put("Invalid ID Pattern", validationRule);

        validationRule = getDummyValidationRule();
        validationRule.setType("XXXXX");
        invalidValidationRules.put("Invalid Type", validationRule);

        validationRule = getDummyValidationRule();
        validationRule.setCountry("EUX");
        invalidValidationRules.put("Invalid Country Pattern", validationRule);

        validationRule = getDummyValidationRule();
        validationRule.setRegion("XXXXXX");
        invalidValidationRules.put("Invalid Region Pattern", validationRule);

        validationRule = getDummyValidationRule();
        validationRule.setVersion("1.0.0.0");
        invalidValidationRules.put("Invalid Version Pattern", validationRule);

        validationRule = getDummyValidationRule();
        validationRule.setSchemaVersion("1.0.0.0");
        invalidValidationRules.put("Invalid Schema Version Pattern", validationRule);

        validationRule = getDummyValidationRule();
        validationRule.setEngineVersion("1.2.3.aaaaa");
        invalidValidationRules.put("Invalid EngineVersion Pattern", validationRule);

        validationRule = getDummyValidationRule();
        validationRule.setDescription(List.of(new ValidationRule.DescriptionItem("xx", "1".repeat(20))));
        invalidValidationRules.put("Missing Description EN", validationRule);

        validationRule = getDummyValidationRule();
        validationRule.getDescription().get(0).setDescription("shorttext");
        invalidValidationRules.put("Description to short", validationRule);

        validationRule = getDummyValidationRule();
        validationRule.setAffectedFields(Collections.emptyList());
        invalidValidationRules.put("AffectedFields No Values", validationRule);

        validationRule = getDummyValidationRule();
        validationRule.setLogic(JsonNodeFactory.instance.objectNode());
        invalidValidationRules.put("Logic Empty", validationRule);

        for (String ruleKey : invalidValidationRules.keySet()) {
            log.info("JSON Schema Check: {}", ruleKey);

            String payload = new SignedStringMessageBuilder()
                .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
                .withPayload(objectMapper.writeValueAsString(invalidValidationRules.get(ruleKey)))
                .buildAsString();

            mockMvc.perform(post("/rules")
                .content(payload)
                .contentType("application/cms")
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
                .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
            )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("0x200"));
        }
    }

    @Test
    void testValidationCountry() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();
        validationRule.setIdentifier("GR-DE-0001");
        validationRule.setCountry("DE");

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.code").value("0x210"));

        validationRule.setCountry("EU");

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.code").value("0x210"));
    }

    @Test
    void testValidationVersion() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x220"));

        validationRule.setVersion("0.9.0");

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x220"));
    }

    @Test
    void testValidationUploadCert() throws Exception {
        ValidationRule validationRule = getDummyValidationRule();

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(
                certificateUtils.convertCertificate(trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "EU")),
                trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, "EU"))
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x230"));
    }

    @Test
    void testValidationTimestamps() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();
        validationRule.setValidFrom(ZonedDateTime.now().plus(1, ChronoUnit.DAYS));
        validationRule.setValidTo(ZonedDateTime.now().minus(1, ChronoUnit.DAYS));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x240"));

        validationRule = getDummyValidationRule();

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        validationRule.setVersion("1.0.1");
        validationRule.setValidFrom(validationRule.getValidFrom().minus(1, ChronoUnit.SECONDS));

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x240"));

        validationRule.setValidFrom(ZonedDateTime.now().plus(4, ChronoUnit.WEEKS));

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x240"));
    }

    @Test
    void testValidationTimestamps2() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();
        validationRule.setIdentifier("IR-EU-0001");
        validationRule.setType("Invalidation");
        validationRule.setValidFrom(ZonedDateTime.now().plus(1, ChronoUnit.MINUTES));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        validationRule = getDummyValidationRule();
        validationRule.setValidFrom(ZonedDateTime.now());

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x240"));
    }

    @Test
    void testValidationTimestamps3() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();
        validationRule.setValidFrom(ZonedDateTime.now().plus(3, ChronoUnit.DAYS));
        validationRule.setValidTo(ZonedDateTime.now()
            .plus(6, ChronoUnit.DAYS)
            .minus(1, ChronoUnit.SECONDS));

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x240"));
    }

    @Test
    void testValidationRuleId() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();
        validationRule.setIdentifier("GR-EU-0001");
        validationRule.setType("Invalidation");

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x250"));

        validationRule.setIdentifier("IR-EU-0001");
        validationRule.setType("Acceptance");

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x250"));

        validationRule.setIdentifier("IR-EU-0001");
        validationRule.setType("Invalidation");

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        validationRule.setIdentifier("GR-EU-0001");
        validationRule.setType("Acceptance");

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());
    }

    @Test
    void testValidationRuleInvalidIdPrefix() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        ValidationRule validationRule = getDummyValidationRule();
        validationRule.setIdentifier("TR-EU-0001");
        validationRule.setCertificateType("Vaccination");

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x250"));

        validationRule.setIdentifier("VR-EU-0001");
        validationRule.setCertificateType("Test");

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x250"));

        validationRule.setIdentifier("RR-EU-0001");
        validationRule.setCertificateType("Vaccination");

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x250"));

        validationRule.setIdentifier("GR-EU-0001");
        validationRule.setCertificateType("Vaccination");

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x250"));
    }

    @Test
    void testDelete() throws Exception {
        long validationRulesInDb = validationRuleRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        validationRule.setVersion("1.0.1");

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        Assertions.assertEquals(validationRulesInDb + 2, validationRuleRepository.count());

        String deletePayload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(validationRule.getIdentifier())
            .buildAsString();

        mockMvc.perform(delete("/rules")
            .content(deletePayload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isNoContent());

        Assertions.assertEquals(validationRulesInDb, validationRuleRepository.count());
    }

    @Test
    void testDeleteFailNotFound() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString("IR-EU-0001"))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(delete("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isNotFound());
    }

    @Test
    void testDeleteFailInvalidUploadCertificate() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString("IR-EU-0001"))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(delete("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x230"));
    }

    @Test
    void testDeleteFailInvalidIdString() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString("XXXX-TESST-!!!!!"))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(delete("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("0x250"));
    }

    @Test
    void testDeleteFailInvalidCountryCode() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString("IR-DE-0001"))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(delete("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.code").value("0x210"));
    }

    @Test
    void testDownloadReturnAll() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        ValidationRule validationRule1 = getDummyValidationRule();
        validationRule1.setValidFrom(ZonedDateTime.now().minus(1, ChronoUnit.DAYS));

        String payload1 = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule1))
            .buildAsString();

        ValidationRuleEntity vr1 = new ValidationRuleEntity();
        vr1.setRuleId(validationRule1.getIdentifier());
        vr1.setValidationRuleType(ValidationRuleEntity.ValidationRuleType.valueOf(validationRule1.getType().toUpperCase(Locale.ROOT)));
        vr1.setValidTo(validationRule1.getValidTo());
        vr1.setValidFrom(validationRule1.getValidFrom());
        vr1.setCountry(validationRule1.getCountry());
        vr1.setCms(payload1);
        vr1.setVersion(validationRule1.getVersion());

        validationRuleRepository.save(vr1);

        ValidationRule validationRule2 = getDummyValidationRule();
        validationRule2.setValidFrom(ZonedDateTime.now().plus(2, ChronoUnit.DAYS));
        validationRule2.setVersion("1.0.1");

        String payload2 = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule2))
            .buildAsString();

        ValidationRuleEntity vr2 = new ValidationRuleEntity();
        vr2.setRuleId(validationRule2.getIdentifier());
        vr2.setValidationRuleType(ValidationRuleEntity.ValidationRuleType.valueOf(validationRule2.getType().toUpperCase(Locale.ROOT)));
        vr2.setValidTo(validationRule2.getValidTo());
        vr2.setValidFrom(validationRule2.getValidFrom());
        vr2.setCountry(validationRule2.getCountry());
        vr2.setCms(payload2);
        vr2.setVersion(validationRule2.getVersion());

        validationRuleRepository.save(vr2);

        ValidationRule validationRule3 = getDummyValidationRule();
        validationRule3.setIdentifier("GR-EU-0002");

        String payload3 = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule3))
            .buildAsString();

        ValidationRuleEntity vr3 = new ValidationRuleEntity();
        vr3.setRuleId(validationRule3.getIdentifier());
        vr3.setValidationRuleType(ValidationRuleEntity.ValidationRuleType.valueOf(validationRule3.getType().toUpperCase(Locale.ROOT)));
        vr3.setValidTo(validationRule3.getValidTo());
        vr3.setValidFrom(validationRule3.getValidFrom());
        vr3.setCountry(validationRule3.getCountry());
        vr3.setCms(payload3);
        vr3.setVersion(validationRule3.getVersion());

        validationRuleRepository.save(vr3);


        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/rules/EU")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.['GR-EU-0001'].length()").value(2))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].version").value(vr2.getVersion()))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].cms").value(vr2.getCms()))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].validTo").value(vr2.getValidTo().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].validFrom").value(vr2.getValidFrom().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0001'][1].version").value(vr1.getVersion()))
            .andExpect(jsonPath("$.['GR-EU-0001'][1].cms").value(vr1.getCms()))
            .andExpect(jsonPath("$.['GR-EU-0001'][1].validTo").value(vr1.getValidTo().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0001'][1].validFrom").value(vr1.getValidFrom().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0002'].length()").value(1))
            .andExpect(jsonPath("$.['GR-EU-0002'][0].version").value(vr3.getVersion()))
            .andExpect(jsonPath("$.['GR-EU-0002'][0].cms").value(vr3.getCms()))
            .andExpect(jsonPath("$.['GR-EU-0002'][0].validTo").value(vr3.getValidTo().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0002'][0].validFrom").value(vr3.getValidFrom().format(formatter)));
    }

    @Test
    void testDownloadReturnOnlyValid() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        ValidationRule validationRule1 = getDummyValidationRule();
        validationRule1.setValidFrom(ZonedDateTime.now().minus(4, ChronoUnit.DAYS));

        String payload1 = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule1))
            .buildAsString();

        ValidationRuleEntity vr1 = new ValidationRuleEntity();
        vr1.setRuleId(validationRule1.getIdentifier());
        vr1.setValidationRuleType(ValidationRuleEntity.ValidationRuleType.valueOf(validationRule1.getType().toUpperCase(Locale.ROOT)));
        vr1.setValidTo(validationRule1.getValidTo());
        vr1.setValidFrom(validationRule1.getValidFrom());
        vr1.setCountry(validationRule1.getCountry());
        vr1.setCms(payload1);
        vr1.setVersion(validationRule1.getVersion());

        validationRuleRepository.save(vr1);

        ValidationRule validationRule2 = getDummyValidationRule();
        validationRule2.setValidFrom(ZonedDateTime.now().minus(2, ChronoUnit.DAYS));
        validationRule2.setVersion("1.0.1");

        String payload2 = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule2))
            .buildAsString();

        ValidationRuleEntity vr2 = new ValidationRuleEntity();
        vr2.setRuleId(validationRule2.getIdentifier());
        vr2.setValidationRuleType(ValidationRuleEntity.ValidationRuleType.valueOf(validationRule2.getType().toUpperCase(Locale.ROOT)));
        vr2.setValidTo(validationRule2.getValidTo());
        vr2.setValidFrom(validationRule2.getValidFrom());
        vr2.setCountry(validationRule2.getCountry());
        vr2.setCms(payload2);
        vr2.setVersion(validationRule2.getVersion());

        validationRuleRepository.save(vr2);

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/rules/EU")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.['GR-EU-0001'].length()").value(1))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].version").value(vr2.getVersion()))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].cms").value(vr2.getCms()))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].validTo").value(vr2.getValidTo().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].validFrom").value(vr2.getValidFrom().format(formatter)));
    }

    @Test
    void testDownloadDbContainsOnlyRulesValidInFutureShouldReturnAll() throws Exception {
        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        ValidationRule validationRule1 = getDummyValidationRule();
        validationRule1.setValidFrom(ZonedDateTime.now().plus(1, ChronoUnit.DAYS));

        String payload1 = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule1))
            .buildAsString();

        ValidationRuleEntity vr1 = new ValidationRuleEntity();
        vr1.setRuleId(validationRule1.getIdentifier());
        vr1.setValidationRuleType(ValidationRuleEntity.ValidationRuleType.valueOf(validationRule1.getType().toUpperCase(Locale.ROOT)));
        vr1.setValidTo(validationRule1.getValidTo());
        vr1.setValidFrom(validationRule1.getValidFrom());
        vr1.setCountry(validationRule1.getCountry());
        vr1.setCms(payload1);
        vr1.setVersion(validationRule1.getVersion());

        validationRuleRepository.save(vr1);

        ValidationRule validationRule2 = getDummyValidationRule();
        validationRule2.setValidFrom(ZonedDateTime.now().plus(2, ChronoUnit.DAYS));
        validationRule2.setVersion("1.0.1");

        String payload2 = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule2))
            .buildAsString();

        ValidationRuleEntity vr2 = new ValidationRuleEntity();
        vr2.setRuleId(validationRule2.getIdentifier());
        vr2.setValidationRuleType(ValidationRuleEntity.ValidationRuleType.valueOf(validationRule2.getType().toUpperCase(Locale.ROOT)));
        vr2.setValidTo(validationRule2.getValidTo());
        vr2.setValidFrom(validationRule2.getValidFrom());
        vr2.setCountry(validationRule2.getCountry());
        vr2.setCms(payload2);
        vr2.setVersion(validationRule2.getVersion());

        validationRuleRepository.save(vr2);

        ValidationRule validationRule3 = getDummyValidationRule();
        validationRule3.setValidFrom(ZonedDateTime.now().plus(3, ChronoUnit.DAYS));
        validationRule3.setVersion("1.1.0");

        String payload3 = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule3))
            .buildAsString();

        ValidationRuleEntity vr3 = new ValidationRuleEntity();
        vr3.setRuleId(validationRule3.getIdentifier());
        vr3.setValidationRuleType(ValidationRuleEntity.ValidationRuleType.valueOf(validationRule3.getType().toUpperCase(Locale.ROOT)));
        vr3.setValidTo(validationRule3.getValidTo());
        vr3.setValidFrom(validationRule3.getValidFrom());
        vr3.setCountry(validationRule3.getCountry());
        vr3.setCms(payload3);
        vr3.setVersion(validationRule3.getVersion());

        validationRuleRepository.save(vr3);


        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/rules/EU")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.['GR-EU-0001'].length()").value(3))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].version").value(vr3.getVersion()))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].cms").value(vr3.getCms()))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].validTo").value(vr3.getValidTo().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0001'][0].validFrom").value(vr3.getValidFrom().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0001'][1].version").value(vr2.getVersion()))
            .andExpect(jsonPath("$.['GR-EU-0001'][1].cms").value(vr2.getCms()))
            .andExpect(jsonPath("$.['GR-EU-0001'][1].validTo").value(vr2.getValidTo().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0001'][1].validFrom").value(vr2.getValidFrom().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0001'][2].version").value(vr1.getVersion()))
            .andExpect(jsonPath("$.['GR-EU-0001'][2].cms").value(vr1.getCms()))
            .andExpect(jsonPath("$.['GR-EU-0001'][2].validTo").value(vr1.getValidTo().format(formatter)))
            .andExpect(jsonPath("$.['GR-EU-0001'][2].validFrom").value(vr1.getValidFrom().format(formatter)));

    }

    @Test
    void testDeleteAliasEndpoint() throws Exception {
        long validationRulesInDb = validationRuleRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        validationRule.setVersion("1.0.1");

        payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        Assertions.assertEquals(validationRulesInDb + 2, validationRuleRepository.count());

        String deletePayload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(validationRule.getIdentifier())
            .buildAsString();

        mockMvc.perform(post("/rules/delete")
            .content(deletePayload)
            .contentType("application/cms")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isNoContent());

        Assertions.assertEquals(validationRulesInDb, validationRuleRepository.count());
    }

    @Test
    void testSuccessfulUploadWithOldContentType() throws Exception {
        long validationRulesInDb = validationRuleRepository.count();
        long auditEventEntitiesInDb = auditEventRepository.count();

        X509Certificate signerCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        PrivateKey signerPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        ValidationRule validationRule = getDummyValidationRule();

        String payload = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(signerCertificate), signerPrivateKey)
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString();

        String authCertHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/rules")
            .content(payload)
            .contentType("application/cms-text")
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
        )
            .andExpect(status().isCreated());

        Assertions.assertEquals(validationRulesInDb + 1, validationRuleRepository.count());
        Optional<ValidationRuleEntity> createdValidationRule =
            validationRuleRepository.getByRuleIdAndVersion(validationRule.getIdentifier(), validationRule.getVersion());

        Assertions.assertTrue(createdValidationRule.isPresent());

        Assertions.assertEquals(auditEventEntitiesInDb + 1, auditEventRepository.count());
        Assertions.assertEquals(validationRule.getValidFrom().toEpochSecond(), createdValidationRule.get().getValidFrom().toEpochSecond());
        Assertions.assertEquals(validationRule.getValidTo().toEpochSecond(), createdValidationRule.get().getValidTo().toEpochSecond());
        Assertions.assertEquals(validationRule.getCountry(), createdValidationRule.get().getCountry());
        Assertions.assertEquals(validationRule.getType().toUpperCase(Locale.ROOT), createdValidationRule.get().getValidationRuleType().toString());

        SignedStringMessageParser parser = new SignedStringMessageParser(createdValidationRule.get().getCms());
        ValidationRule parsedValidationRule = objectMapper.readValue(parser.getPayload(), ValidationRule.class);

        assertEquals(validationRule, parsedValidationRule);
    }
}
