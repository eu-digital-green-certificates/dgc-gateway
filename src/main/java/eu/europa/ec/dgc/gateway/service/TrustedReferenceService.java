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
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedReferenceEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedReferenceRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDeleteRequestDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDto;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.util.List;
import java.util.Optional;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;


@Slf4j
@Service
@RequiredArgsConstructor
public class TrustedReferenceService {

    private final TrustedReferenceRepository trustedReferenceRepository;

    private final CertificateUtils certificateUtils;

    private final TrustedPartyService trustedPartyService;

    private final ObjectMapper objectMapper;

    private static final String MDC_PROP_UPLOAD_CERT_THUMBPRINT = "uploadCertThumbprint";


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
                    "Requested TrustedReferencec not available.")
        );
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

        TrustedReferenceEntity trustedReferenceEntity = new TrustedReferenceEntity();
        trustedReferenceEntity.setCountry(parsedTrustedEntity.getCountry());
        trustedReferenceEntity.setType(
                TrustedReferenceEntity.ReferenceType.valueOf(parsedTrustedEntity.getType().name()));
        trustedReferenceEntity.setService(parsedTrustedEntity.getService());
        trustedReferenceEntity.setName(parsedTrustedEntity.getName());
        trustedReferenceEntity.setSignatureType(
                TrustedReferenceEntity.SignatureType.valueOf(parsedTrustedEntity.getSignatureType().name()));
        trustedReferenceEntity.setThumbprint(parsedTrustedEntity.getThumbprint());
        trustedReferenceEntity.setSslPublicKey(parsedTrustedEntity.getSslPublicKey());

        log.info("Saving new Trusted Reference Entity with uuid {}", trustedReferenceEntity.getUuid());

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

    private <T> T contentCheckValidJson(String json, Class<T> clazz) throws TrustedReferenceServiceException {

        try {
            objectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
            return objectMapper.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new TrustedReferenceServiceException(TrustedReferenceServiceException.Reason.INVALID_JSON,
                    "JSON could not be parsed");
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
