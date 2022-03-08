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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedReferenceEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedReferenceRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDeleteRequestDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDto;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;


@Slf4j
@Service
@RequiredArgsConstructor
public class TrustedReferenceService {

    private final TrustedReferenceRepository trustedReferenceRepository;
    private final CertificateUtils certificateUtils;
    private final TrustedPartyService trustedPartyService;
    private final ObjectMapper objectMapper;
    private final Validator validator;

    private static final String MDC_PROP_UPLOAD_CERT_THUMBPRINT = "uploadCertThumbprint";


    /**
     * Deletes all TrustedReferences assigned to given source gateway.
     *
     * @param gatewayId GatewayID of source gateway
     */
    public void deleteBySourceGateway(String gatewayId) {
        log.info("Deleting TrustedReferences by GatewayId {}", gatewayId);

        Long deleteCount = trustedReferenceRepository.deleteBySourceGatewayGatewayId(gatewayId);

        log.info("Deleted {} TrustedReferences with GatewayId {}", deleteCount, gatewayId);
    }

    /**
     * Method to query the db for all trusted references.
     *
     * @return List holding the found trusted references.
     */
    public List<TrustedReferenceEntity> getAllReferences() {
        return trustedReferenceRepository.findAll();
    }

    /**
     * Method to query the db for one trusted reference.
     *
     * @return trusted reference.
     */
    public TrustedReferenceEntity getReference(final String uuid) throws TrustedReferenceServiceException {
        return trustedReferenceRepository.getByUuid(uuid).orElseThrow(
            () -> new TrustedReferenceServiceException(TrustedReferenceServiceException.Reason.NOT_FOUND,
                "Requested TrustedReference not available.")
        );
    }

    /**
     * Search for TrustedReferences by given criteria.
     *
     * @param country        List of possible values for country
     * @param domain         List of possible values for domain
     * @param types          List of possible values for reference type
     * @param signatureTypes List of possible values for signatue type
     * @param withFederation flag whether federated data should be included.
     * @return List of matching entities.
     */
    public List<TrustedReferenceEntity> search(List<String> country, List<String> domain, List<String> types,
                                               List<String> signatureTypes, boolean withFederation) {

        final List<TrustedReferenceEntity.ReferenceType> parsedTypes = new ArrayList<>();
        if (types != null) {
            types.forEach(type -> {
                if (TrustedReferenceEntity.ReferenceType.stringValues().contains(type)) {
                    parsedTypes.add(TrustedReferenceEntity.ReferenceType.valueOf(type));
                }
            });
        }

        final List<TrustedReferenceEntity.SignatureType> parsedSignatureTypes = new ArrayList<>();
        if (signatureTypes != null) {
            signatureTypes.forEach(type -> {
                if (TrustedReferenceEntity.SignatureType.stringValues().contains(type)) {
                    parsedSignatureTypes.add(TrustedReferenceEntity.SignatureType.valueOf(type));
                }
            });
        }

        if (withFederation) {
            return trustedReferenceRepository.search(
                country, country == null || country.isEmpty(),
                domain, domain == null || domain.isEmpty(),
                parsedTypes, parsedTypes.isEmpty(),
                parsedSignatureTypes, parsedSignatureTypes.isEmpty());
        } else {
            return trustedReferenceRepository.searchNonFederated(
                country, country == null || country.isEmpty(),
                domain, domain == null || domain.isEmpty(),
                parsedTypes, parsedTypes.isEmpty(),
                parsedSignatureTypes, parsedSignatureTypes.isEmpty());
        }

    }

    /**
     * Add a new federated TrustedReference.
     */
    public TrustedReferenceEntity addFederatedTrustedReference(String country,
                                                               TrustedReferenceEntity.ReferenceType referenceType,
                                                               String service,
                                                               String name,
                                                               TrustedReferenceEntity.SignatureType signatureType,
                                                               String thumbprint,
                                                               String sslPublicKey,
                                                               String referenceVersion,
                                                               String contentType,
                                                               String domain,
                                                               String uuid,
                                                               FederationGatewayEntity sourceGateway) {
        TrustedReferenceEntity trustedReferenceEntity = new TrustedReferenceEntity();
        trustedReferenceEntity.setCountry(country);
        trustedReferenceEntity.setType(referenceType);
        trustedReferenceEntity.setService(service);
        trustedReferenceEntity.setName(name);
        trustedReferenceEntity.setSignatureType(signatureType);
        trustedReferenceEntity.setThumbprint(thumbprint);
        trustedReferenceEntity.setSslPublicKey(sslPublicKey);
        trustedReferenceEntity.setReferenceVersion(referenceVersion);
        trustedReferenceEntity.setContentType(contentType);
        trustedReferenceEntity.setSourceGateway(sourceGateway);
        trustedReferenceEntity.setDomain(domain == null ? "DCC" : domain);
        if (uuid == null) {
            trustedReferenceEntity.setUuid(UUID.randomUUID().toString());
        }

        log.info("Saving Federated Trusted Reference Entity with uuid {}", trustedReferenceEntity.getUuid());

        trustedReferenceEntity = trustedReferenceRepository.save(trustedReferenceEntity);

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);

        return trustedReferenceEntity;
    }

    /**
     * Add a new TrustedReference.
     */
    public TrustedReferenceEntity addTrustedReference(
        String uploadedTrustedReference,
        X509CertificateHolder signerCertificate,
        String authenticatedCountryCode
    ) throws TrustedReferenceServiceException {

        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        TrustedReferenceDto parsedTrustedEntity =
            contentCheckValidJson(uploadedTrustedReference, TrustedReferenceDto.class);
        contentCheckUploaderCountry(parsedTrustedEntity, authenticatedCountryCode);
        contentCheckValidValues(parsedTrustedEntity);

        TrustedReferenceEntity trustedReferenceEntity = getOrCreateTrustedReferenceEntity(parsedTrustedEntity);

        trustedReferenceEntity.setCountry(parsedTrustedEntity.getCountry());
        trustedReferenceEntity.setType(
            TrustedReferenceEntity.ReferenceType.valueOf(parsedTrustedEntity.getType().name()));
        trustedReferenceEntity.setService(parsedTrustedEntity.getService());
        trustedReferenceEntity.setName(parsedTrustedEntity.getName());
        trustedReferenceEntity.setSignatureType(
            TrustedReferenceEntity.SignatureType.valueOf(parsedTrustedEntity.getSignatureType().name()));
        trustedReferenceEntity.setThumbprint(parsedTrustedEntity.getThumbprint());
        trustedReferenceEntity.setSslPublicKey(parsedTrustedEntity.getSslPublicKey());
        trustedReferenceEntity.setReferenceVersion(parsedTrustedEntity.getReferenceVersion());
        trustedReferenceEntity.setContentType(parsedTrustedEntity.getContentType());
        trustedReferenceEntity.setDomain(
            parsedTrustedEntity.getDomain() == null ? "DCC" : parsedTrustedEntity.getDomain());
        if (parsedTrustedEntity.getUuid() == null) {
            trustedReferenceEntity.setUuid(UUID.randomUUID().toString());
        }

        log.info("Saving Trusted Reference Entity with uuid {}", trustedReferenceEntity.getUuid());

        trustedReferenceEntity = trustedReferenceRepository.save(trustedReferenceEntity);

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);

        return trustedReferenceEntity;
    }

    /**
     * Delete a Trusted Reference.
     */
    public void deleteTrustedReference(
        String uuidJson,
        X509CertificateHolder signerCertificate,
        String authenticatedCountryCode
    ) throws TrustedReferenceServiceException {

        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        TrustedReferenceDeleteRequestDto parsedDeleteRequest =
            contentCheckValidJson(uuidJson, TrustedReferenceDeleteRequestDto.class);

        final String uuid = parsedDeleteRequest.getUuid();
        TrustedReferenceEntity trustedReferenceEntity = trustedReferenceRepository.getByUuid(uuid).orElseThrow(
            () -> new TrustedReferenceServiceException(TrustedReferenceServiceException.Reason.NOT_FOUND,
                "Trusted Reference does not exist.")
        );

        log.info("Deleting Trusted Reference with uuid {} and id {}from DB", uuid, trustedReferenceEntity.getId());
        int deleted = trustedReferenceRepository.deleteByUuid(uuid);

        if (deleted == 1) {
            log.info("Deleted Trusted Reference with uuid {}", uuid);
        } else {
            log.warn("Could not delete Trusted Reference with uuid {}", uuid);
        }

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);
    }

    private TrustedReferenceEntity getOrCreateTrustedReferenceEntity(TrustedReferenceDto parsedTrustedEntity)
        throws TrustedReferenceServiceException {
        TrustedReferenceEntity trustedReferenceEntity;
        final String uuidRequest = parsedTrustedEntity.getUuid();
        if (StringUtils.isNotEmpty(uuidRequest)) {
            log.info("Updating Trusted Reference with uuid {}", uuidRequest);
            trustedReferenceEntity = trustedReferenceRepository.getByUuid(parsedTrustedEntity.getUuid())
                .orElseThrow(() ->
                    new TrustedReferenceServiceException(TrustedReferenceServiceException.Reason.NOT_FOUND,
                        "Trusted Reference to be updated not found."));
        } else {
            trustedReferenceEntity = new TrustedReferenceEntity();
            log.info("Creating new Trusted Reference with uuid {}", trustedReferenceEntity.getUuid());
        }
        return trustedReferenceEntity;
    }

    private <T> T contentCheckValidJson(String json, Class<T> clazz) throws TrustedReferenceServiceException {

        try {
            objectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
            return objectMapper.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new TrustedReferenceServiceException(TrustedReferenceServiceException.Reason.INVALID_JSON,
                "JSON could not be parsed");
        }
    }

    private void contentCheckValidValues(TrustedReferenceDto parsedTrustedReference)
        throws TrustedReferenceServiceException {

        ArrayList<String> errorMessages = new ArrayList<>();

        Errors errors = new BeanPropertyBindingResult(parsedTrustedReference, TrustedReferenceDto.class.getName());
        validator.validate(parsedTrustedReference, errors);

        if (errors.hasErrors()) {
            errors.getFieldErrors()
                .forEach(error -> errorMessages.add(error.getField() + ": " + error.getDefaultMessage()));
        }

        if (!errorMessages.isEmpty()) {
            throw new TrustedReferenceServiceException(TrustedReferenceServiceException.Reason.INVALID_JSON_VALUES,
                String.join(", ", errorMessages)
            );
        }
    }

    /**
     * Checks a given UploadCertificate if it exists in the database and is assigned to given CountryCode.
     *
     * @param signerCertificate        Upload Certificate
     * @param authenticatedCountryCode Country Code.
     * @throws TrustedReferenceServiceException if Validation fails.
     */
    public void contentCheckUploaderCertificate(
        X509CertificateHolder signerCertificate,
        String authenticatedCountryCode) throws TrustedReferenceServiceException {
        // Content Check Step 1: Uploader Certificate
        String signerCertThumbprint = certificateUtils.getCertThumbprint(signerCertificate);
        Optional<TrustedPartyEntity> certFromDb = trustedPartyService.getCertificate(
            signerCertThumbprint,
            authenticatedCountryCode,
            TrustedPartyEntity.CertificateType.UPLOAD
        );

        if (certFromDb.isEmpty()) {
            throw new TrustedReferenceServiceException(
                TrustedReferenceServiceException.Reason.UPLOADER_CERT_CHECK_FAILED,
                "Could not find upload certificate with hash %s and country %s",
                signerCertThumbprint, authenticatedCountryCode);
        }

        DgcMdc.put(MDC_PROP_UPLOAD_CERT_THUMBPRINT, signerCertThumbprint);
    }

    private void contentCheckUploaderCountry(TrustedReferenceDto parsedTrustedReference, String countryCode)
            throws TrustedReferenceServiceException {
        if (!parsedTrustedReference.getCountry().equals(countryCode)) {
            throw new TrustedReferenceServiceException(TrustedReferenceServiceException.Reason.INVALID_COUNTRY,
                    "Country does not match your authentication.");
        }
    }

    public static class TrustedReferenceServiceException extends Exception {

        @Getter
        private final Reason reason;

        public TrustedReferenceServiceException(Reason reason, String message, Object... args) {
            super(String.format(message, args));
            this.reason = reason;
        }

        public enum Reason {
            INVALID_JSON,
            INVALID_JSON_VALUES,
            INVALID_COUNTRY,
            UPLOADER_CERT_CHECK_FAILED,
            NOT_FOUND,
            GONE
        }
    }
}
