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

package eu.europa.ec.dgc.gateway.service;

import static eu.europa.ec.dgc.gateway.utils.CmsUtils.getSignedString;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.entity.RevocationBatchEntity;
import eu.europa.ec.dgc.gateway.entity.RevocationBatchProjection;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.model.RevocationBatchDownload;
import eu.europa.ec.dgc.gateway.model.RevocationBatchList;
import eu.europa.ec.dgc.gateway.repository.RevocationBatchRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.CmsPackageDto;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedStringDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationBatchDeleteRequestDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationBatchDto;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.Errors;
import org.springframework.validation.FieldError;
import org.springframework.validation.Validator;

@Service
@Slf4j
@RequiredArgsConstructor
public class RevocationListService {

    private static final int MAX_BATCH_LIST_SIZE = 1000;

    private final RevocationBatchRepository revocationBatchRepository;

    private final CertificateUtils certificateUtils;

    private final TrustedPartyService trustedPartyService;

    private final ObjectMapper objectMapper;

    private final Validator validator;

    private final AuditService auditService;

    private static final String MDC_PROP_UPLOAD_CERT_THUMBPRINT = "uploadCertThumbprint";

    /**
     * Deletes batch with given batchId.
     *
     * @param batchId to delete
     * @return amount of deleted entities.
     */
    public int deleteRevocationBatchByBatchId(String batchId) {
        return revocationBatchRepository.deleteByBatchId(batchId);
    }

    /**
     * Adds a new Validation Rule DB.
     *
     * @param uploadedRevocationBatch  the JSON String with the uploaded batch.
     * @param signerCertificate        the certificate which was used to sign the message
     * @param cms                      the cms containing the JSON
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @throws RevocationBatchServiceException if validation check has failed. The exception contains a reason property
     *                                         with detailed information why the validation has failed.
     */
    public RevocationBatchEntity addRevocationBatch(
        String uploadedRevocationBatch,
        X509CertificateHolder signerCertificate,
        String cms,
        String authenticatedCountryCode
    ) throws RevocationBatchServiceException {

        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        RevocationBatchDto parsedBatch = contentCheckValidJson(uploadedRevocationBatch, RevocationBatchDto.class);
        contentCheckValidValues(parsedBatch);
        contentCheckUploaderCountry(parsedBatch, authenticatedCountryCode);


        // All checks passed --> Save to DB
        RevocationBatchEntity newRevocationBatchEntity = new RevocationBatchEntity();
        newRevocationBatchEntity.setBatchId(UUID.randomUUID().toString());
        newRevocationBatchEntity.setCountry(parsedBatch.getCountry());
        newRevocationBatchEntity.setExpires(parsedBatch.getExpires());
        newRevocationBatchEntity.setKid(parsedBatch.getKid());
        newRevocationBatchEntity.setType(
            RevocationBatchEntity.RevocationHashType.valueOf(parsedBatch.getHashType().name()));
        newRevocationBatchEntity.setChanged(ZonedDateTime.now());
        newRevocationBatchEntity.setDeleted(false);
        newRevocationBatchEntity.setSignedBatch(cms);

        log.info("Saving new Revocation Batch Entity with id {}", newRevocationBatchEntity.getBatchId());

        auditService.addAuditEvent(
            authenticatedCountryCode,
            signerCertificate,
            authenticatedCountryCode,
            "CREATED",
            String.format("Uploaded Revocation Batch (%s)", newRevocationBatchEntity.getBatchId())
        );

        newRevocationBatchEntity = revocationBatchRepository.save(newRevocationBatchEntity);

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);

        return newRevocationBatchEntity;
    }

    /**
     * Deletes a Revocation Batch from DB.
     *
     * @param batchIdJson              the JSON String with the id of the batch to delete.
     * @param signerCertificate        the certificate which was used to sign the message
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @throws RevocationBatchServiceException if validation check has failed. The exception contains a reason property
     *                                         with detailed information why the validation has failed.
     */
    public void deleteRevocationBatch(
        String batchIdJson,
        X509CertificateHolder signerCertificate,
        String authenticatedCountryCode
    ) throws RevocationBatchServiceException {

        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        RevocationBatchDeleteRequestDto parsedDeleteRequest =
            contentCheckValidJson(batchIdJson, RevocationBatchDeleteRequestDto.class);
        contentCheckValidValuesForDeletion(parsedDeleteRequest);

        Optional<RevocationBatchEntity> entityInDb =
            revocationBatchRepository.getByBatchId(parsedDeleteRequest.getBatchId());

        if (entityInDb.isEmpty()) {
            throw new RevocationBatchServiceException(RevocationBatchServiceException.Reason.NOT_FOUND,
                "Revocation Batch does not exists");
        }

        if (!entityInDb.get().getCountry().equals(authenticatedCountryCode)) {
            throw new RevocationBatchServiceException(RevocationBatchServiceException.Reason.INVALID_COUNTRY,
                "Revocation Batch does not belong to your country");
        }

        if (entityInDb.get().getDeleted()) {
            throw new RevocationBatchServiceException(RevocationBatchServiceException.Reason.GONE,
                "Revocation Batch is already deleted.");
        }

        log.info("Deleting Revocation Batch with Batch ID {} from DB", parsedDeleteRequest.getBatchId());

        revocationBatchRepository.markBatchAsDeleted(parsedDeleteRequest.getBatchId());

        auditService.addAuditEvent(
            authenticatedCountryCode,
            signerCertificate,
            authenticatedCountryCode,
            "DELETED",
            String.format("Deleted Revocation Batch (%s)", parsedDeleteRequest.getBatchId())
        );

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);
    }

    /**
     * Returns a RevocationBatchList with Revocation Batches later than given threshold date.
     * Result is limited to 1000 entries.
     *
     * @param thresholdDate date to filter the entries.
     * @return RevocationBatchList with entries and more flag set to true if more batches exists.
     */
    public RevocationBatchList getRevocationBatchList(ZonedDateTime thresholdDate) {

        RevocationBatchList batchList = new RevocationBatchList();

        List<RevocationBatchProjection> entityList =
            revocationBatchRepository.getAllByChangedGreaterThanOrderByChangedAsc(
                thresholdDate, PageRequest.ofSize(MAX_BATCH_LIST_SIZE + 1));

        batchList.setMore(entityList.size() > MAX_BATCH_LIST_SIZE);
        batchList.setBatches(entityList.stream()
            .limit(MAX_BATCH_LIST_SIZE)
            .map(revocationBatchEntity -> new RevocationBatchList.RevocationBatchListItem(
                revocationBatchEntity.getBatchId(),
                revocationBatchEntity.getCountry(),
                revocationBatchEntity.getChanged(),
                revocationBatchEntity.getDeleted()
            ))
            .collect(Collectors.toList())
        );

        return batchList;
    }

    /**
     * Download a single revocation batch with the corresponding CMS.
     *
     * @param batchId Batch ID of the Batch to download.
     * @return Object holding the CMS and BatchID.
     * @throws RevocationBatchServiceException if Download fails with information about the reason.
     */
    public RevocationBatchDownload getRevocationBatch(String batchId) throws RevocationBatchServiceException {
        Optional<RevocationBatchEntity> entity = revocationBatchRepository.getByBatchId(batchId);

        if (entity.isEmpty()) {
            throw new RevocationBatchServiceException(
                RevocationBatchServiceException.Reason.NOT_FOUND, "Batch not found");
        }

        if (entity.get().getDeleted()) {
            throw new RevocationBatchServiceException(
                RevocationBatchServiceException.Reason.GONE, "Batch already deleted.");
        }

        return new RevocationBatchDownload(entity.get().getBatchId(), entity.get().getSignedBatch());
    }

    /**
     * Get CMS packages for country.
     *
     * @param country The country
     * @return A list of all CMS Packages.
     */
    public List<CmsPackageDto> getCmsPackage(String country) {
        List<RevocationBatchEntity> revocationBatchEntities = revocationBatchRepository.getAllByCountry(country);
        return revocationBatchEntities.stream()
                .filter(it -> !it.getDeleted())
                .map(it -> new CmsPackageDto(it.getSignedBatch(), it.getId(),
                        CmsPackageDto.CmsPackageTypeDto.REVOCATION_LIST))
                .collect(Collectors.toList());
    }

    /**
     * Update Revocation Batch with new cms in db.
     *
     * @param id                       the id of the entity.
     * @param signerCertificate        the certificate which was used to sign the message
     * @param cms                      the cms containing the JSON
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @throws RevocationBatchServiceException if validation check has failed. The exception contains a reason property
     *                                         with detailed information why the validation has failed.
     */
    public RevocationBatchEntity updateRevocationBatchCertificate(
            Long id,
            String payloadRevocationBatch,
            X509CertificateHolder signerCertificate,
            String cms,
            String authenticatedCountryCode
    ) throws RevocationBatchServiceException {

        final RevocationBatchEntity revocationBatchEntity = revocationBatchRepository.findById(id).orElseThrow(
            () -> new RevocationBatchServiceException(RevocationBatchServiceException.Reason.NOT_FOUND,
                "RevocationBatch not present."));

        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        contentCheckUploaderCountry(revocationBatchEntity.getCountry(), authenticatedCountryCode);
        contentCheckMigrateCms(payloadRevocationBatch, revocationBatchEntity.getSignedBatch());

        revocationBatchEntity.setSignedBatch(cms);
        revocationBatchEntity.setChanged(ZonedDateTime.now());

        log.info("Updating cms of Revocation Batch Entity with id {}", revocationBatchEntity.getBatchId());

        auditService.addAuditEvent(
                authenticatedCountryCode,
                signerCertificate,
                authenticatedCountryCode,
                "UPDATED",
                String.format("Updated Revocation Batch (%s)", revocationBatchEntity.getBatchId())
        );

        RevocationBatchEntity updatedEntity = revocationBatchRepository.save(revocationBatchEntity);

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);

        return updatedEntity;
    }

    private void contentCheckUploaderCountry(RevocationBatchDto parsedBatch, String countryCode)
        throws RevocationBatchServiceException {
        contentCheckUploaderCountry(parsedBatch.getCountry(), countryCode);
    }

    private void contentCheckUploaderCountry(String batchCountryCode, String countryCode)
            throws RevocationBatchServiceException {
        if (!batchCountryCode.equals(countryCode)) {
            throw new RevocationBatchServiceException(
                    RevocationBatchServiceException.Reason.INVALID_COUNTRY,
                    "Country does not match your authentication.");
        }
    }

    private <T> T contentCheckValidJson(String json, Class<T> clazz) throws RevocationBatchServiceException {

        try {
            objectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
            return objectMapper.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new RevocationBatchServiceException(
                RevocationBatchServiceException.Reason.INVALID_JSON,
                "JSON could not be parsed");
        }
    }


    private void contentCheckValidValues(RevocationBatchDto parsedBatch) throws RevocationBatchServiceException {

        ArrayList<String> errorMessages = new ArrayList<>();

        Errors errors = new BeanPropertyBindingResult(parsedBatch, RevocationBatchDto.class.getName());
        validator.validate(parsedBatch, errors);

        if (errors.hasErrors()) {
            errors.getFieldErrors()
                .forEach(error -> {
                    errorMessages.add(error.getField() + ": " + error.getDefaultMessage());
                });
        }

        for (int i = 0; i < parsedBatch.getEntries().size(); i++) {
            Errors batchEntryErrors = new BeanPropertyBindingResult(parsedBatch.getEntries().get(i),
                RevocationBatchDto.BatchEntryDto.class.getName());

            validator.validate(parsedBatch.getEntries().get(i), batchEntryErrors);

            if (batchEntryErrors.hasErrors()) {
                for (FieldError error : batchEntryErrors.getFieldErrors()) {
                    errorMessages.add("Batch Entry " + i + ": " + error.getField() + ": " + error.getDefaultMessage());
                }
            }
        }

        if (!errorMessages.isEmpty()) {
            throw new RevocationBatchServiceException(
                RevocationBatchServiceException.Reason.INVALID_JSON_VALUES,
                String.join(", ", errorMessages)
            );
        }
    }

    private void contentCheckValidValuesForDeletion(RevocationBatchDeleteRequestDto parsedDeleteRequest)
        throws RevocationBatchServiceException {

        ArrayList<String> errorMessages = new ArrayList<>();

        Errors errors =
            new BeanPropertyBindingResult(parsedDeleteRequest, RevocationBatchDeleteRequestDto.class.getName());
        validator.validate(parsedDeleteRequest, errors);

        if (errors.hasErrors()) {
            errors.getFieldErrors()
                .forEach(error -> {
                    errorMessages.add(error.getField() + ": " + error.getDefaultMessage());
                });
        }

        if (!errorMessages.isEmpty()) {
            throw new RevocationBatchServiceException(
                RevocationBatchServiceException.Reason.INVALID_JSON_VALUES,
                String.join(", ", errorMessages)
            );
        }
    }

    private void contentCheckMigrateCms(String payload, String entityCms)
            throws RevocationBatchServiceException {
        SignedStringDto signedStringDto = getSignedString(entityCms);
        if (!payload.equals(signedStringDto.getPayloadString())) {
            throw new RevocationBatchServiceException(
                    RevocationBatchServiceException.Reason.INVALID_JSON_VALUES,
                    "New cms payload does not match present payload."
            );
        }
    }

    /**
     * Checks a given UploadCertificate if it exists in the database and is assigned to given CountryCode.
     *
     * @param signerCertificate        Upload Certificate
     * @param authenticatedCountryCode Country Code.
     * @throws RevocationBatchServiceException if Validation fails.
     */
    public void contentCheckUploaderCertificate(
        X509CertificateHolder signerCertificate,
        String authenticatedCountryCode) throws RevocationBatchServiceException {
        // Content Check Step 1: Uploader Certificate
        String signerCertThumbprint = certificateUtils.getCertThumbprint(signerCertificate);
        Optional<TrustedPartyEntity> certFromDb = trustedPartyService.getCertificate(
            signerCertThumbprint,
            authenticatedCountryCode,
            TrustedPartyEntity.CertificateType.UPLOAD
        );

        if (certFromDb.isEmpty()) {
            throw new RevocationBatchServiceException(RevocationBatchServiceException.Reason.UPLOADER_CERT_CHECK_FAILED,
                "Could not find upload certificate with hash %s and country %s",
                signerCertThumbprint, authenticatedCountryCode);
        }

        DgcMdc.put(MDC_PROP_UPLOAD_CERT_THUMBPRINT, signerCertThumbprint);
    }

    public static class RevocationBatchServiceException extends Exception {

        @Getter
        private final Reason reason;

        public RevocationBatchServiceException(Reason reason, String message, Object... args) {
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
