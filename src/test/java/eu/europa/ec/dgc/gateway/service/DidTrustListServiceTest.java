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

import static org.mockito.Mockito.doNothing;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.FederationGatewayRepository;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.repository.TrustedIssuerRepository;
import eu.europa.ec.dgc.gateway.repository.TrustedPartyRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.did.DidTrustListDto;
import eu.europa.ec.dgc.gateway.service.did.DidTrustListService;
import eu.europa.ec.dgc.gateway.service.did.DidUploader;
import eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.gateway.testdata.TrustedIssuerTestHelper;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

@SpringBootTest
public class DidTrustListServiceTest {


    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    DidTrustListService didTrustListService;

    @Autowired
    SignerInformationRepository signerInformationRepository;

    @Autowired
    TrustedPartyRepository trustedPartyRepository;

    @Autowired
    FederationGatewayRepository federationGatewayRepository;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    TrustListService trustListService;

    @Autowired
    TrustedIssuerRepository trustedIssuerRepository;

    @Autowired
    TrustedIssuerTestHelper trustedIssuerTestHelper;

    @Autowired
    CertificateUtils certificateUtils;

    @MockBean
    DidUploader didUploaderMock;

    X509Certificate certUploadDe, certUploadEu, certCscaDe, certCscaEu, certAuthDe, certAuthEu, certDscDe, certDscEu,
        federatedCertDscEx;

    FederationGatewayEntity federationGateway;

    @BeforeEach
    void testData() throws Exception {
        trustedPartyRepository.deleteAll();
        signerInformationRepository.deleteAll();
        federationGatewayRepository.deleteAll();

        federationGateway =
            new FederationGatewayEntity(null, ZonedDateTime.now(), "gw-id", "endpoint", "kid", "pk", "impl",
                FederationGatewayEntity.DownloadTarget.FEDERATION, FederationGatewayEntity.Mode.APPEND, "sig", -1L,
                null, null, 0L, null, null);
        federationGateway = federationGatewayRepository.save(federationGateway);

        certUploadDe = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "DE");
        certUploadEu = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "EU");
        certCscaDe = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "DE");
        certCscaEu = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "EU");
        certAuthDe = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.AUTHENTICATION, "DE");
        certAuthEu = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.AUTHENTICATION, "EU");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ec");
        certDscDe =
            CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "DE", "Test", certCscaDe,
                trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.AUTHENTICATION, "DE"));
        certDscEu =
            CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "EU", "Test", certCscaEu,
                trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.AUTHENTICATION, "EU"));

        signerInformationRepository.save(new SignerInformationEntity(
            null,
            ZonedDateTime.now(),
            "DE",
            certificateUtils.getCertThumbprint(certDscDe),
            Base64.getEncoder().encodeToString(certDscDe.getEncoded()),
            "sig1",
            "kid1",
            SignerInformationEntity.CertificateType.DSC,
            null
        ));

        signerInformationRepository.save(new SignerInformationEntity(
            null,
            ZonedDateTime.now(),
            "EU",
            certificateUtils.getCertThumbprint(certDscEu),
            Base64.getEncoder().encodeToString(certDscEu.getEncoded()),
            "sig2",
            "kid2",
            SignerInformationEntity.CertificateType.DSC,
            null
        ));

        federatedCertDscEx = CertificateTestUtils.generateCertificate(keyPairGenerator.generateKeyPair(), "EX", "Test");
        SignerInformationEntity federatedDscEntity = new SignerInformationEntity(
            null,
            ZonedDateTime.now(),
            "EX",
            certificateUtils.getCertThumbprint(federatedCertDscEx),
            Base64.getEncoder().encodeToString(federatedCertDscEx.getEncoded()),
            "sig3",
            "kid3",
            SignerInformationEntity.CertificateType.DSC,
            null
        );
        federatedDscEntity.setSourceGateway(federationGateway);
        signerInformationRepository.save(federatedDscEntity);

        trustedIssuerRepository.save(trustedIssuerTestHelper.createTrustedIssuer("DE", "DCC"));
        trustedIssuerRepository.save(trustedIssuerTestHelper.createTrustedIssuer("EU", "DCC"));
        trustedIssuerRepository.save(trustedIssuerTestHelper.createTrustedIssuer("XY", "DCC"));
    }

    @Test
    void testTrustList() throws IOException, CertificateEncodingException {
        ArgumentCaptor<byte[]> uploadArgumentCaptor = ArgumentCaptor.forClass(byte[].class);
        doNothing().when(didUploaderMock).uploadDid(uploadArgumentCaptor.capture());

        didTrustListService.job();

        SignedDidTrustListDto parsed = objectMapper.readValue(uploadArgumentCaptor.getValue(), SignedDidTrustListDto.class);

        Assertions.assertEquals("a", parsed.getId());
        Assertions.assertEquals("b", parsed.getController());
        Assertions.assertEquals(6, parsed.getVerificationMethod().size());

        assertVerificationMethod(parsed.getVerificationMethod().get(0), "kid1", certDscDe, certCscaDe);
        assertVerificationMethod(parsed.getVerificationMethod().get(1), "kid2", certDscEu, certCscaEu);
        assertVerificationMethod(parsed.getVerificationMethod().get(2), "kid3", federatedCertDscEx, null);

        Assertions.assertTrue(parsed.getVerificationMethod().contains("did:trusted:DE:issuer"));
        Assertions.assertTrue(parsed.getVerificationMethod().contains("did:trusted:EU:issuer"));
        Assertions.assertTrue(parsed.getVerificationMethod().contains("did:trusted:XY:issuer"));
        Assertions.assertEquals(2, parsed.getContext().size());
        Assertions.assertEquals("JsonWebSignature2020", parsed.getProof().getType());
        Assertions.assertTrue(Instant.now().toEpochMilli() - parsed.getProof().getCreated().toInstant().toEpochMilli() < 1000);
        Assertions.assertEquals("f", parsed.getProof().getDomain());
        Assertions.assertEquals("g", parsed.getProof().getNonce());
        Assertions.assertEquals("assertionMethod", parsed.getProof().getProofPurpose());
        Assertions.assertEquals("e", parsed.getProof().getVerificationMethod());
        Assertions.assertNotNull(parsed.getProof().getJws());
        Assertions.assertNotEquals("", parsed.getProof().getJws());

    }

    private void assertVerificationMethod(Object in, String kid, X509Certificate dsc, X509Certificate csca)
        throws CertificateEncodingException {
        LinkedHashMap jsonNode = (LinkedHashMap) in;
        Assertions.assertEquals("JsonWebKey2020", jsonNode.get("type"));
        Assertions.assertEquals("d", jsonNode.get("controller"));
        Assertions.assertEquals("c" + kid, jsonNode.get("id"));

        LinkedHashMap publicKeyJwk = (LinkedHashMap) jsonNode.get("publicKeyJwk");

        Assertions.assertEquals(((ECPublicKey) dsc.getPublicKey()).getW().getAffineX(), new BigInteger(Base64.getDecoder().decode(publicKeyJwk.get("x").toString())));
        Assertions.assertEquals(((ECPublicKey) dsc.getPublicKey()).getW().getAffineY(), new BigInteger(Base64.getDecoder().decode(publicKeyJwk.get("y").toString())));
        Assertions.assertEquals("EC", publicKeyJwk.get("kty").toString());
        Assertions.assertEquals("P-256", publicKeyJwk.get("crv").toString());
        ArrayList<String> x5c = ((ArrayList<String>) publicKeyJwk.get("x5c"));
        Assertions.assertEquals(Base64.getEncoder().encodeToString(dsc.getEncoded()), x5c.get(0));
        if (csca != null) {
            Assertions.assertEquals(Base64.getEncoder().encodeToString(csca.getEncoded()), x5c.get(1));
        }
    }

    @Getter
    @Setter
    public static class SignedDidTrustListDto extends DidTrustListDto {

        private LDProof proof;

        @Data
        private static class LDProof {

            private String type;

            private ZonedDateTime created;

            private String verificationMethod;

            private String proofPurpose;

            private String jws;

            private String domain;

            private String nonce;

        }
    }
}
