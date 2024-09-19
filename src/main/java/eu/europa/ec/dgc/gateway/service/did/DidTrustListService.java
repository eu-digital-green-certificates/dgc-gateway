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
import com.nimbusds.jose.util.Base64URL;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.model.TrustedCertificateTrustList;
import eu.europa.ec.dgc.gateway.restapi.dto.did.DidTrustListDto;
import eu.europa.ec.dgc.gateway.restapi.dto.did.DidTrustListEntryDto;
import eu.europa.ec.dgc.gateway.service.TrustListService;
import eu.europa.ec.dgc.gateway.service.TrustedIssuerService;
import eu.europa.ec.dgc.gateway.service.TrustedPartyService;
import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.JsonWebSignature2020LdSigner;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.jetbrains.annotations.NotNull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;


@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty("dgc.did.enableDidGeneration")
public class DidTrustListService {

    private static final String SEPARATOR_COLON = ":";

    private static final String SEPARATOR_FRAGMENT = "#";

    private static final List<String> DID_CONTEXTS = List.of(
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1");

    private final TrustedIssuerService trustedIssuerService;

    private final TrustListService trustListService;

    private final DgcConfigProperties configProperties;

    private final ByteSigner byteSigner;

    private final DidUploadInvoker didUploadInvoker;

    private final ObjectMapper objectMapper;

    private final TrustedPartyService trustedPartyService;

    /**
     * Create and upload DID Document holding Uploaded DSC and Trusted Issuer.
     */
    @Scheduled(cron = "${dgc.trustlist.cron}")
    @SchedulerLock(name = "didTrustListGenerator")
    public void job() {
        String trustList;
        try {
            trustList = generateTrustList(null);
        } catch (Exception e) {
            log.error("Failed to generate DID-TrustList: {}", e.getMessage());
            return;
        }

        try {
            didUploadInvoker.uploadDid(trustList.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.error("Failed to Upload DID-TrustList: {}", e.getMessage());
            return;
        }

        List<String> countries = trustedPartyService.getCountryList();

        for (String country : countries) {
            String countryTrustList = null;
            List<String> countryAsList = List.of(country);
            String countryAsSubcontainer = getCountryAsLowerCaseAlpha3(country);
            if (countryAsSubcontainer != null) {
                try {
                    countryTrustList = generateTrustList(countryAsList);
                } catch (Exception e) {
                    log.error("Failed to generate DID-TrustList for country {} : {}", country, e.getMessage());
                    continue;
                }

                try {
                    didUploadInvoker
                    .uploadDid(countryAsSubcontainer, countryTrustList.getBytes(StandardCharsets.UTF_8));
                } catch (Exception e) {
                    log.error("Failed to Upload DID-TrustList for country {} : {}", country, e.getMessage());
                }
            }
        }

        log.info("Finished DID Export Process");
    }

    private String getCountryAsLowerCaseAlpha3(String country) {
        if (country == null || country.length() != 2 && country.length() != 3) {
            return null;
        } else if (country.length() == 3) {
            return country.toLowerCase();
        }

        return configProperties.getCountryCodeMap().getVirtualCountries()
            .compute(country, (alpha2, alpha3) -> {
                if (alpha3 != null) {
                    return alpha3.toLowerCase();
                }

                try {
                    return new Locale("en", alpha2).getISO3Country().toLowerCase();
                } catch (MissingResourceException e) {
                    log.error("Country Code to alpha 3 conversion issue for country {} : {}",
                        country, e.getMessage());
                    return null;
                }
            });
    }

    private String generateTrustList(List<String> countries) throws Exception {
        DidTrustListDto trustList = new DidTrustListDto();
        trustList.setContext(DID_CONTEXTS);
        trustList.setId(configProperties.getDid().getDidId());
        trustList.setController(configProperties.getDid().getDidController());
        trustList.setVerificationMethod(new ArrayList<>());

        if (countries != null && !countries.isEmpty()) {
            trustList.setId(configProperties.getDid().getDidId()
                    + SEPARATOR_COLON
                    + getCountryAsLowerCaseAlpha3(countries.get(0)));
            trustList.setController(configProperties.getDid().getDidController()
                    + SEPARATOR_COLON
                    + getCountryAsLowerCaseAlpha3(countries.get(0)));
        }

        // Add DSC
        List<TrustedCertificateTrustList> certs = trustListService.getTrustedCertificateTrustList(
            SignerInformationEntity.CertificateType.stringValues(),
            countries,
            null,
            configProperties.getDid().getIncludeFederated()
        );

        for (TrustedCertificateTrustList cert : certs) {

            PublicKey publicKey = cert.getParsedCertificate().getPublicKey();

            if (publicKey instanceof RSAPublicKey rsaPublicKey) {
                addTrustListEntry(trustList, cert,
                    new DidTrustListEntryDto.RsaPublicKeyJwk(rsaPublicKey, List.of(cert.getCertificate())));

            } else if (publicKey instanceof ECPublicKey ecPublicKey) {
                addTrustListEntry(trustList, cert,
                    new DidTrustListEntryDto.EcPublicKeyJwk(ecPublicKey, List.of(cert.getCertificate())));

            } else {
                log.error("Public Key is not RSA or EC Public Key for cert {} of country {}",
                    cert.getThumbprint(),
                    cert.getCountry());
            }
        }

        // Add TrustedIssuer
        trustedIssuerService.search(
                null, countries, configProperties.getDid().getIncludeFederated()).stream()
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

    private void addTrustListEntry(DidTrustListDto trustList,
                                   TrustedCertificateTrustList cert,
                                   DidTrustListEntryDto.PublicKeyJwk publicKeyJwk)
            throws CertificateEncodingException, UnsupportedEncodingException {
        Optional<TrustedCertificateTrustList> csca = searchForIssuer(cert);

        if (csca.isPresent()) {
            publicKeyJwk.getEncodedX509Certificates()
                .add(Base64.getEncoder().encodeToString(csca.get().getParsedCertificate().getEncoded()));
        }

        DidTrustListEntryDto trustListEntry = new DidTrustListEntryDto();
        trustListEntry.setType("JsonWebKey2020");
        trustListEntry.setId(configProperties.getDid().getTrustListIdPrefix()
                + SEPARATOR_COLON
                + getCountryAsLowerCaseAlpha3(cert.getCountry())
                + SEPARATOR_FRAGMENT
                + getEncodedKid(cert.getKid()));;
        trustListEntry.setController(configProperties.getDid().getTrustListControllerPrefix()
                + SEPARATOR_COLON + getCountryAsLowerCaseAlpha3(cert.getCountry()));
        trustListEntry.setPublicKeyJwk(publicKeyJwk);

        trustList.getVerificationMethod().add(trustListEntry);
    }

    @NotNull
    private Optional<TrustedCertificateTrustList> searchForIssuer(TrustedCertificateTrustList cert) {
        // Search for Issuer of DSC
        return trustListService.getTrustedCertificateTrustList(
                List.of(TrustedPartyEntity.CertificateType.CSCA.name()),
                List.of(cert.getCountry()),
                List.of(cert.getDomain()),
                configProperties.getDid().getIncludeFederated()).stream()
            .filter(tp -> tp.getParsedCertificate().getSubjectX500Principal()
                .equals(cert.getParsedCertificate().getIssuerX500Principal()))
            .findFirst();
    }

    private String getEncodedKid(String kid) {
        return Base64URL.encode(kid).toString();
    }
}
