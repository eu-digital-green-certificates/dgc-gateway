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

package eu.europa.ec.dgc.gateway.service.did;

import com.apicatalog.jsonld.document.JsonDocument;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.restapi.dto.did.DidTrustListDto;
import eu.europa.ec.dgc.gateway.restapi.dto.did.DidTrustListEntryDto;
import eu.europa.ec.dgc.gateway.service.SignerInformationService;
import eu.europa.ec.dgc.gateway.service.TrustedIssuerService;
import eu.europa.ec.dgc.gateway.service.TrustedPartyService;
import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.JsonWebSignature2020LdSigner;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty("dgc.did.enableDidGeneration")
public class DidTrustListService {

    private static final List<String> DID_CONTEXTS = List.of(
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1");

    private final TrustedPartyService trustedPartyService;

    private final SignerInformationService signerInformationService;

    private final TrustedIssuerService trustedIssuerService;

    private final DgcConfigProperties configProperties;

    private final ByteSigner byteSigner;

    private final DidUploader didUploader;

    private final ObjectMapper objectMapper;

    /**
     * Create and upload DID Document holding Uploaded DSC and Trusted Issuer.
     */
    @Scheduled(cron = "0 0 * * * *")
    @SchedulerLock(name = "didTrustListGenerator")
    public void job() {
        String trustList;
        try {
            trustList = generateTrustList();
        } catch (Exception e) {
            log.error("Failed to generate DID-TrustList: {}", e.getMessage());
            return;
        }

        try {
            didUploader.uploadDid(trustList.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.error("Failed to Upload DID-TrustList: {}", e.getMessage());
            return;
        }
        log.info("Finished DID Export Process");
    }

    private String generateTrustList() throws Exception {
        DidTrustListDto trustList = new DidTrustListDto();
        trustList.setContext(DID_CONTEXTS);
        trustList.setId(configProperties.getDid().getDidId());
        trustList.setController(configProperties.getDid().getDidController());
        trustList.setVerificationMethod(new ArrayList<>());


        // Add DSC
        List<SignerInformationEntity> certs = signerInformationService.getSignerInformation(
            null, null, null, configProperties.getDid().getIncludeFederated());

        for (SignerInformationEntity cert : certs) {
            DidTrustListEntryDto.EcPublicKeyJwk.EcPublicKeyJwkBuilder<?, ?> jwkBuilder =
                DidTrustListEntryDto.EcPublicKeyJwk.builder();

            X509Certificate x509 = signerInformationService.getX509CertificateFromEntity(cert);

            ECPublicKey publicKey = (ECPublicKey) x509.getPublicKey();
            jwkBuilder.valueX(Base64.getEncoder().encodeToString(publicKey.getW().getAffineX().toByteArray()));
            jwkBuilder.valueY(Base64.getEncoder().encodeToString(publicKey.getW().getAffineY().toByteArray()));

            ECNamedCurveSpec curveSpec = (ECNamedCurveSpec) publicKey.getParams();
            if (curveSpec.getName().equals("prime256v1")) {
                jwkBuilder.curve("P-256");
            } else if (curveSpec.getName().equals("prime384v1")) {
                jwkBuilder.curve("P-384");
            } else if (curveSpec.getName().equals("prime521v1")) {
                jwkBuilder.curve("P-521");
            }

            jwkBuilder.keyType("EC");
            jwkBuilder.encodedX509Certificates(new ArrayList<>(List.of(cert.getRawData())));
            DidTrustListEntryDto.EcPublicKeyJwk jwk = jwkBuilder.build();

            Optional<X509Certificate> csca =
                trustedPartyService.getCertificate(cert.getCountry(), TrustedPartyEntity.CertificateType.CSCA).stream()
                    .map(trustedPartyService::getX509CertificateFromEntity)
                    .filter(tp -> tp.getSubjectDN().equals(x509.getIssuerDN()))
                    .findFirst();

            if (csca.isPresent()) {
                jwk.getEncodedX509Certificates().add(Base64.getEncoder().encodeToString(csca.get().getEncoded()));
            }

            DidTrustListEntryDto trustListEntry = new DidTrustListEntryDto();
            trustListEntry.setType("JsonWebKey2020");
            trustListEntry.setId(configProperties.getDid().getTrustListIdPrefix() + cert.getKid());
            trustListEntry.setController(configProperties.getDid().getTrustListControllerPrefix());
            trustListEntry.setPublicKeyJwk(jwk);

            trustList.getVerificationMethod().add(trustListEntry);
        }

        // Add TrustedIssuer
        trustedIssuerService.search(
                null, null, configProperties.getDid().getIncludeFederated()).stream()
            .filter(trustedIssuer -> trustedIssuer.getUrlType() == TrustedIssuerEntity.UrlType.DID)
            .forEach(trustedIssuer -> trustList.getVerificationMethod().add(trustedIssuer.getUrl()));

        // Create LD-Proof Document
        JsonWebSignature2020LdSigner signer = new JsonWebSignature2020LdSigner(byteSigner);
        signer.setCreated(new Date());
        signer.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD);
        signer.setVerificationMethod(URI.create(configProperties.getDid().getLdProofVerificationMethod()));
        signer.setDomain(configProperties.getDid().getLdProofDomain());
        signer.setNonce(configProperties.getDid().getLdProofNonce());

        // Load DID-Contexts
        Map<URI, JsonDocument> contextMap = new HashMap<>();
        for (String didContext : DID_CONTEXTS) {
            String didContextFile = configProperties.getDid().getContextMapping().get(didContext);

            if (didContextFile == null) {
                log.error("Failed to load DID-Context Document for {}: No Mapping to local JSON-File.", didContext);

            }

            try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(
                "did_contexts/" + didContextFile)) {
                if (inputStream != null) {
                    contextMap.put(URI.create(didContext), JsonDocument.of(inputStream));
                }
            } catch (Exception e) {
                log.error("Failed to load DID-Context Document {}: {}", didContextFile, e.getMessage());
                throw e;
            }
        }
        JsonLDObject jsonLdObject = JsonLDObject.fromJson(objectMapper.writeValueAsString(trustList));
        jsonLdObject.setDocumentLoader(new ConfigurableDocumentLoader(contextMap));

        signer.sign(jsonLdObject);

        return jsonLdObject.toJson();
    }
}
