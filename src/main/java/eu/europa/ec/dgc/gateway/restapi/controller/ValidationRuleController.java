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

import eu.europa.ec.dgc.gateway.config.OpenApiConfig;
import eu.europa.ec.dgc.gateway.entity.ValidationRuleEntity;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.converter.CmsStringMessageConverter;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedStringDto;
import eu.europa.ec.dgc.gateway.restapi.dto.ValidationRuleDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationFilter;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwValidationRuleMapper;
import eu.europa.ec.dgc.gateway.service.AuditService;
import eu.europa.ec.dgc.gateway.service.ValidationRuleService;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.validator.constraints.Length;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rules")
@Slf4j
@RequiredArgsConstructor
public class ValidationRuleController {

    private final ValidationRuleService validationRuleService;

    private final AuditService auditService;

    private final GwValidationRuleMapper validationRuleMapper;

    private static final String MDC_VALIDATION_RULE_DOWNLOAD_AMOUNT = "validationDownloadAmount";
    private static final String MDC_VALIDATION_RULE_DOWNLOAD_REQUESTER = "validationDownloadRequester";
    private static final String MDC_VALIDATION_RULE_DOWNLOAD_REQUESTED = "validationDownloadRequested";
    private static final String MDC_VALIDATION_RULE_DELETE_ID = "validationDownloadId";
    private static final String MDC_VALIDATION_RULE_DELETE_AMOUNT = "validationDeleteAmount";

    /**
     * Endpoint to download a Validation Rule.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/{country}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Download all rules of country.",
        tags = {"Validation Rules"},
        parameters = {
            @Parameter(
                in = ParameterIn.PATH,
                name = "country",
                required = true,
                example = "EU")
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Download successful.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(ref = "#/components/schemas/ValidationRuleDownloadResponse")
                ))
        }
    )
    public ResponseEntity<Map<String, List<ValidationRuleDto>>> downloadValidationRules(
        @Valid @PathVariable("country") @Length(max = 2, min = 2) String requestedCountryCode,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String requesterCountryCode
    ) {

        log.info("Rule Download Request");

        List<ValidationRuleEntity> validationRuleEntities =
            validationRuleService.getActiveValidationRules(requestedCountryCode);

        Map<String, List<ValidationRuleDto>> map = new HashMap<>();

        validationRuleEntities.forEach(validationRuleEntitiy ->
            map.computeIfAbsent(validationRuleEntitiy.getRuleId(), k -> new ArrayList<>())
                .add(validationRuleMapper.entityToDto(validationRuleEntitiy)));

        DgcMdc.put(MDC_VALIDATION_RULE_DOWNLOAD_AMOUNT, validationRuleEntities.size());
        DgcMdc.put(MDC_VALIDATION_RULE_DOWNLOAD_REQUESTER, requesterCountryCode);
        DgcMdc.put(MDC_VALIDATION_RULE_DOWNLOAD_REQUESTED, requestedCountryCode);
        log.info("Rule Download Success");

        return ResponseEntity.ok(map);
    }

    /**
     * Endpoint to upload a Validation Rule.
     */
    @CertificateAuthenticationRequired
    @PostMapping(path = "", consumes = {
        CmsStringMessageConverter.CONTENT_TYPE_CMS_TEXT_VALUE, CmsStringMessageConverter.CONTENT_TYPE_CMS_VALUE})
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Create a new versions of a rule with id",
        tags = {"Validation Rules"},
        requestBody = @RequestBody(
            required = true,
            description = "CMS Signed String with Validation Rule. Needs to be signed with valid Upload Certificate"
        ),
        responses = {
            @ApiResponse(
                responseCode = "201",
                description = "Created successful."),
            @ApiResponse(
                responseCode = "400",
                description = "Bad data submitted. See ProblemReport for more details.",
                content = @Content(schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "403",
                description = "You are not allowed to create this validation rules.",
                content = @Content(schema = @Schema(implementation = ProblemReportDto.class)))
        }
    )
    public ResponseEntity<Void> uploadValidationRule(
        @org.springframework.web.bind.annotation.RequestBody SignedStringDto signedJson,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String authenticatedCountryCode,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT) String thumbprint
    ) {

        log.info("Rule Upload Request");

        if (!signedJson.isVerified()) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x260", "CMS signature is invalid", "",
                "Submitted string needs to be signed by a valid upload certificate");
        }

        ValidationRuleEntity createdValidationRule;

        try {
            createdValidationRule = validationRuleService.addValidationRule(
                signedJson.getPayloadString(),
                signedJson.getSignerCertificate(),
                signedJson.getRawMessage(),
                authenticatedCountryCode);
        } catch (ValidationRuleService.ValidationRuleCheckException e) {
            DgcMdc.put("validationRuleUploadError", e.getMessage());
            DgcMdc.put("validationRuleUploadReason", e.getReason().toString());
            log.error("Rule Upload Failed");

            switch (e.getReason()) {
                case INVALID_JSON:
                    throw new DgcgResponseException(
                        HttpStatus.BAD_REQUEST, "0x200", "Invalid JSON", "", e.getMessage());
                case INVALID_COUNTRY:
                    throw new DgcgResponseException(HttpStatus.FORBIDDEN, "0x210", "Invalid Country sent", "",
                        e.getMessage());
                case INVALID_VERSION:
                    throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x220", "Invalid Version", "",
                        e.getMessage());
                case UPLOADER_CERT_CHECK_FAILED:
                    throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x230", "Invalid Upload Cert",
                        signedJson.getSignerCertificate().getSubject().toString(), e.getMessage());
                case INVALID_TIMESTAMP:
                    throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x240", "Invalid Timestamp(s)",
                        "", e.getMessage());
                case INVALID_RULE_ID:
                    throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x250", "Invalid RuleID",
                        "", e.getMessage());
                default:
                    throw new DgcgResponseException(HttpStatus.INTERNAL_SERVER_ERROR, "0x299", "Unexpected Error",
                        "", "");
            }
        }


        log.info("Rule Upload Success");

        auditService.addAuditEvent(
            authenticatedCountryCode,
            signedJson.getSignerCertificate(),
            thumbprint,
            "CREATED",
            String.format("Created Validation Rule with ID %s (%s)",
                createdValidationRule.getRuleId(), createdValidationRule.getVersion()));

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * Endpoint to delete a Validation Rule.
     */
    @CertificateAuthenticationRequired
    @DeleteMapping(path = "", consumes = {
        CmsStringMessageConverter.CONTENT_TYPE_CMS_TEXT_VALUE, CmsStringMessageConverter.CONTENT_TYPE_CMS_VALUE})
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Delete all versions of a rule with id",
        tags = {"Validation Rules"},
        requestBody = @RequestBody(
            required = true,
            description = "CMS Signed String representing the Rule ID. Needs to be signed with valid Upload Certificate"
        ),
        responses = {
            @ApiResponse(
                responseCode = "204",
                description = "Delete successful."),
            @ApiResponse(
                responseCode = "400",
                description = "Bad data submitted. See ProblemReport for more details.",
                content = @Content(schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "403",
                description = "You are not allowed to delete these validation rules.",
                content = @Content(schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "404",
                description = "Validation rule not found.",
                content = @Content(schema = @Schema(implementation = ProblemReportDto.class)))
        }
    )
    public ResponseEntity<Void> deleteValidationRules(
        @org.springframework.web.bind.annotation.RequestBody SignedStringDto signedString,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String authenticatedCountryCode,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT) String thumbprint) {

        log.info("Rule Delete Request");

        if (!signedString.isVerified()) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x260", "CMS signature is invalid", "",
                "Submitted string needs to be signed by a valid upload certificate");
        }

        try {
            validationRuleService.contentCheckUploaderCertificate(
                signedString.getSignerCertificate(), authenticatedCountryCode);
        } catch (ValidationRuleService.ValidationRuleCheckException e) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x230", "Invalid Upload certificate", "",
                "You have to use a onboarded upload certificate to sign the string");
        }

        String countryCodeFromIdString =
            validationRuleService.getCountryCodeFromIdString(signedString.getPayloadString());

        if (countryCodeFromIdString == null) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x250", "ID-String is invalid",
                signedString.getPayloadString(), "Example valid ID-String: GR-EU-11100");
        }

        if (!countryCodeFromIdString.equals(authenticatedCountryCode)) {
            throw new DgcgResponseException(HttpStatus.FORBIDDEN, "0x210", "Invalid country in ID-String",
                String.format(
                    "Your authenticated country code: %s, Your requested country code: %s",
                    authenticatedCountryCode, countryCodeFromIdString),
                "ID-String needs to contain your Country Code.");
        }

        int deleted = validationRuleService.deleteByRuleId(signedString.getPayloadString());

        if (deleted == 0) {
            throw new DgcgResponseException(HttpStatus.NOT_FOUND, "0x270", "Validation Rule does not exist",
                String.format("Validation-Rule Id: %s", signedString.getPayloadString()),
                "You can only delete existing validation rules.");
        }

        DgcMdc.put(MDC_VALIDATION_RULE_DELETE_AMOUNT, deleted);
        DgcMdc.put(MDC_VALIDATION_RULE_DELETE_ID, signedString.getPayloadString());
        log.info("Rule Delete Success");

        auditService.addAuditEvent(
            authenticatedCountryCode,
            signedString.getSignerCertificate(),
            thumbprint,
            "DELETED",
            "Deleted Validation Rule with ID " + signedString.getPayloadString());

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    /**
     * Alias endpoint to delete a Validation Rule.
     */
    @CertificateAuthenticationRequired
    @PostMapping(path = "/delete", consumes = {
        CmsStringMessageConverter.CONTENT_TYPE_CMS_TEXT_VALUE, CmsStringMessageConverter.CONTENT_TYPE_CMS_VALUE})
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Delete all versions of a rule with id (Alias Endpoint for DELETE)",
        tags = {"Validation Rules"},
        requestBody = @RequestBody(
            required = true,
            description = "CMS Signed String representing the Rule ID. Needs to be signed with valid Upload Certificate"
        ),
        responses = {
            @ApiResponse(
                responseCode = "204",
                description = "Delete successful."),
            @ApiResponse(
                responseCode = "400",
                description = "Bad data submitted. See ProblemReport for more details.",
                content = @Content(schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "403",
                description = "You are not allowed to delete these validation rules.",
                content = @Content(schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "404",
                description = "Validation rule not found.",
                content = @Content(schema = @Schema(implementation = ProblemReportDto.class)))
        }
    )
    public ResponseEntity<Void> deleteValidationRulesAliasEndpoint(
        @org.springframework.web.bind.annotation.RequestBody SignedStringDto signedString,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String authenticatedCountryCode,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT) String thumbprint
    ) {
        return deleteValidationRules(signedString, authenticatedCountryCode, thumbprint);
    }
}
