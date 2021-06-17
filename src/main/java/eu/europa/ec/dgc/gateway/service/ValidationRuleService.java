/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vdurmont.semver4j.Semver;
import eu.europa.ec.dgc.gateway.config.ValidationRuleSchemaProvider;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.entity.ValidationRuleEntity;
import eu.europa.ec.dgc.gateway.model.ParsedValidationRule;
import eu.europa.ec.dgc.gateway.repository.ValidationRuleRepository;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class ValidationRuleService {

    private final ValidationRuleRepository validationRuleRepository;

    private final CertificateUtils certificateUtils;

    private final TrustedPartyService trustedPartyService;

    private final ValidationRuleSchemaProvider validationRuleSchemaProvider;

    private static final String MDC_PROP_UPLOAD_CERT_THUMBPRINT = "uploadCertThumbprint";

    /**
     * Queries the database for Validation Rules filtered by country.
     *
     * @param country 2 Digit Country Code
     * @return List of ValidationRule Entities.
     */
    public List<ValidationRuleEntity> getValidationRulesByCountry(String country) {
        return validationRuleRepository.getAllByCountry(country);
    }

    /**
     * Deletes all rules with given ID.
     *
     * @param ruleId to delete
     * @return amount of deleted entities.
     */
    public int deleteByRuleId(String ruleId) {
        int deleted = validationRuleRepository.deleteByRuleId(ruleId);

        DgcMdc.put("deletedAmount", deleted);
        DgcMdc.put("ruleId", ruleId);
        log.info("Deleted Validation Rules");

        return deleted;
    }

    /**
     * Gets the 2 Digit Country Code from a ID String (e.g. GR-EU-13330 -> EU)
     *
     * @param idString the idString to parse
     * @return the 2 digit country code or null if parsing has failed.
     */
    public String getCountryCodeFromIdString(String idString) {
        String[] parts = idString.split("-");

        if (parts.length != 3) {
            return null;
        }

        if (parts[1].length() != 2) {
            return null;
        }

        return parts[1];
    }

    /**
     * Adds a new Validation Rule DB.
     *
     * @param uploadedRule             the JSON String with the uploaded rule.
     * @param signerCertificate        the certificate which was used to sign the message
     * @param cms                      the cms containing the JSON
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @throws ValidationRuleCheckException if validation check has failed. The exception contains
     *                                      a reason property with detailed information why the validation has failed.
     */
    public ValidationRuleEntity addValidationRule(
        String uploadedRule,
        X509CertificateHolder signerCertificate,
        String cms,
        String authenticatedCountryCode
    ) throws ValidationRuleCheckException {

        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        ParsedValidationRule parsedValidationRule = contentCheckValidJson(uploadedRule);

        ValidationRuleEntity.ValidationRuleType validationRuleType =
            parsedValidationRule.getType().equals("Acceptance") ? ValidationRuleEntity.ValidationRuleType.ACCEPTANCE
                : ValidationRuleEntity.ValidationRuleType.INVALIDATION;

        contentCheckUploaderCountry(parsedValidationRule, authenticatedCountryCode);
        contentCheckTimestamps(parsedValidationRule, validationRuleType);
        contentCheckVersion(parsedValidationRule);

        // All checks passed --> Save to DB
        ValidationRuleEntity newValidationRule = new ValidationRuleEntity();
        newValidationRule.setValidationRuleType(validationRuleType);
        newValidationRule.setCountry(parsedValidationRule.getCountry());
        newValidationRule.setRuleId(parsedValidationRule.getIdentifier());
        newValidationRule.setValidTo(parsedValidationRule.getValidTo());
        newValidationRule.setValidFrom(parsedValidationRule.getValidFrom());
        newValidationRule.setCms(cms);
        newValidationRule.setVersion(parsedValidationRule.getVersion());

        log.info("Saving new ValidationRule Entity");

        newValidationRule = validationRuleRepository.save(newValidationRule);

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);

        return newValidationRule;
    }

    private void contentCheckVersion(ParsedValidationRule parsedValidationRule) throws ValidationRuleCheckException {
        // Get latest version in DB
        List<ValidationRuleEntity> validationRules =
            validationRuleRepository.getAllByRuleId(parsedValidationRule.getIdentifier());

        if (validationRules.isEmpty()) {
            return;
        }

        String latestVersion = validationRules.stream()
            .max(Comparator.comparing(v -> new Semver(v.getVersion())))
            .get().getVersion();

        if (new Semver(parsedValidationRule.getVersion()).isLowerThanOrEqualTo(new Semver(latestVersion))) {
            throw new ValidationRuleCheckException(
                ValidationRuleCheckException.Reason.INVALID_VERSION,
                "Version of new rule needs to be greater then old version. Latest Version is ", latestVersion
            );
        }
    }

    private void contentCheckTimestamps(
        ParsedValidationRule parsedValidationRule, ValidationRuleEntity.ValidationRuleType type)
        throws ValidationRuleCheckException {

        if (!parsedValidationRule.getValidTo().isAfter(parsedValidationRule.getValidFrom())) {
            throw new ValidationRuleCheckException(
                ValidationRuleCheckException.Reason.INVALID_TIMESTAMP,
                "ValidFrom needs to be before ValidTo."
            );
        }

        if (type == ValidationRuleEntity.ValidationRuleType.ACCEPTANCE
            && parsedValidationRule.getValidFrom()
            .isBefore(ZonedDateTime.now().plus(48, ChronoUnit.HOURS))) {

            throw new ValidationRuleCheckException(
                ValidationRuleCheckException.Reason.INVALID_TIMESTAMP,
                "ValidFrom needs to be at least 48h in future for Acceptance Validation Rules");
        }

        if (type == ValidationRuleEntity.ValidationRuleType.INVALIDATION
            && parsedValidationRule.getValidFrom().isBefore(ZonedDateTime.now())) {

            throw new ValidationRuleCheckException(
                ValidationRuleCheckException.Reason.INVALID_TIMESTAMP,
                "ValidFrom needs to be in future for Invalidation Rules");
        }

        if (parsedValidationRule.getValidFrom().isBefore(parsedValidationRule.getValidTo())) {
            throw new ValidationRuleCheckException(
                ValidationRuleCheckException.Reason.INVALID_TIMESTAMP,
                "ValidFrom needs to be after ValidTo"
            );
        }

    }

    private void contentCheckUploaderCountry(ParsedValidationRule parsedValidationRule, String countryCode)
        throws ValidationRuleCheckException {
        if (!parsedValidationRule.getCountry().equals(countryCode)) {
            throw new ValidationRuleCheckException(
                ValidationRuleCheckException.Reason.INVALID_COUNTRY,
                "Country does not match your authentication.");
        }

        if (!getCountryCodeFromIdString(parsedValidationRule.getIdentifier()).equals(countryCode)) {
            throw new ValidationRuleCheckException(
                ValidationRuleCheckException.Reason.INVALID_COUNTRY,
                "Country Code in Identifier does not match country.");
        }
    }

    private ParsedValidationRule contentCheckValidJson(String json) throws ValidationRuleCheckException {
        Schema validationSchema = validationRuleSchemaProvider.getValidationRuleSchema();

        try {
            JSONObject jsonObject = new JSONObject(json);
            validationSchema.validate(jsonObject);
        } catch (JSONException e) {
            throw new ValidationRuleCheckException(
                ValidationRuleCheckException.Reason.INVALID_JSON,
                "JSON could not be parsed");
        } catch (ValidationException validationException) {
            throw new ValidationRuleCheckException(
                ValidationRuleCheckException.Reason.INVALID_JSON,
                "JSON does not align to Validation Rule Schema", validationException.toJSON().toString());
        }

        try {
            return new ObjectMapper().readValue(json, ParsedValidationRule.class);
        } catch (JsonProcessingException e) {
            throw new ValidationRuleCheckException(
                ValidationRuleCheckException.Reason.INVALID_JSON,
                "JSON could not be parsed");
        }
    }

    /**
     * Checks a given UploadCertificate if it exists in the database and is assigned to given CountryCode.
     *
     * @param signerCertificate        Upload Certificate
     * @param authenticatedCountryCode Country Code.
     * @throws ValidationRuleCheckException if Validation fails.
     */
    public void contentCheckUploaderCertificate(
        X509CertificateHolder signerCertificate,
        String authenticatedCountryCode) throws ValidationRuleCheckException {
        // Content Check Step 1: Uploader Certificate
        String signerCertThumbprint = certificateUtils.getCertThumbprint(signerCertificate);
        Optional<TrustedPartyEntity> certFromDb = trustedPartyService.getCertificate(
            signerCertThumbprint,
            authenticatedCountryCode,
            TrustedPartyEntity.CertificateType.UPLOAD
        );

        if (certFromDb.isEmpty()) {
            throw new ValidationRuleCheckException(ValidationRuleCheckException.Reason.UPLOADER_CERT_CHECK_FAILED,
                "Could not find upload certificate with hash %s and country %s",
                signerCertThumbprint, authenticatedCountryCode);
        }

        DgcMdc.put(MDC_PROP_UPLOAD_CERT_THUMBPRINT, signerCertThumbprint);
    }

    public static class ValidationRuleCheckException extends Exception {

        @Getter
        private final Reason reason;

        public ValidationRuleCheckException(Reason reason, String message, Object... args) {
            super(String.format(message, args));
            this.reason = reason;
        }

        public enum Reason {
            INVALID_JSON,
            INVALID_COUNTRY,
            INVALID_TIMESTAMP,
            INVALID_VERSION,
            UPLOADER_CERT_CHECK_FAILED,
        }
    }

}
