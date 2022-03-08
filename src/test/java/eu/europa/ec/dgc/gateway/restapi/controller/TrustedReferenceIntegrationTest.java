package eu.europa.ec.dgc.gateway.restapi.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.ser.ZonedDateTimeSerializer;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedReferenceEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedReferenceRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDeleteRequestDto;
import eu.europa.ec.dgc.gateway.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.utils.CertificateUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatterBuilder;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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
}
