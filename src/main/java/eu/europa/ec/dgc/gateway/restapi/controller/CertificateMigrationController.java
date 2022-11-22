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

import static eu.europa.ec.dgc.gateway.utils.CmsUtils.getSignedString;
import static eu.europa.ec.dgc.gateway.utils.CmsUtils.getSignerCertificate;

import eu.europa.ec.dgc.gateway.config.OpenApiConfig;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.dto.CmsPackageDto;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedCertificateDto;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedStringDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationFilter;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.service.RevocationListService;
import eu.europa.ec.dgc.gateway.service.SignerInformationService;
import eu.europa.ec.dgc.gateway.service.ValidationRuleService;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/cms-migration")
@Slf4j
@RequiredArgsConstructor
public class CertificateMigrationController {

    public static final String SENT_VALUES_FORMAT = "{%s} country:{%s}";
    public static final String X_004 = "0x004";
    public static final String DEFAULT_ERROR_MESSAGE = "Possible reasons: Wrong Format,"
        + " no CMS, not the correct signing alg missing attributes, invalid signature, "
        + "certificate not signed by known CA";

    private final SignerInformationService signerInformationService;

    private final RevocationListService revocationListService;

    private final ValidationRuleService validationRuleService;

    private static final String MDC_VERIFICATION_ERROR_REASON = "verificationFailureReason";
    private static final String MDC_VERIFICATION_ERROR_MESSAGE = "verificationFailureMessage";

    /**
     * Get CMS Packages for country.
     */
    @CertificateAuthenticationRequired
    @GetMapping
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Get all cms packages for a country identified by certificate.",
        tags = {"CMS Migration"},
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Download successful.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = CmsPackageDto.class)
                ))
        }
    )
    public ResponseEntity<List<CmsPackageDto>> getCmsPackages(
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String countryCode
    ) {

        log.info("Getting cms packages for {}", countryCode);

        List<CmsPackageDto> listItems = signerInformationService.getCmsPackage(countryCode);
        log.info("Found {} signerInformation DSC entries", listItems.size());

        List<CmsPackageDto> revocationList = revocationListService.getCmsPackage(countryCode);
        log.info("Found {} revocation entries", revocationList.size());
        listItems.addAll(revocationList);

        List<CmsPackageDto> validationList = validationRuleService.getCmsPackage(countryCode);
        log.info("Found {} validation rule entries", validationList.size());
        listItems.addAll(validationList);

        return ResponseEntity.ok(listItems);
    }

    /**
     * Update a CMS Package.
     */
    @CertificateAuthenticationRequired
    @PostMapping
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        tags = {"CMS Migration"},
        summary = "Update an existing CMS Package",
        description = "Endpoint to update an existing CMS pacakage.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            content = @Content(schema = @Schema(implementation = CmsPackageDto.class))
        ),
        responses = {
            @ApiResponse(
                responseCode = "204",
                description = "Update applied."),
            @ApiResponse(
                responseCode = "409",
                description = "CMS Package does not exist."),
            @ApiResponse(
                responseCode = "400",
                description = "Invalid CMS input.")
        }
    )
    public ResponseEntity<Void> updateCmsPackage(
        @RequestBody CmsPackageDto cmsPackageDto,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String countryCode,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT) String authThumbprint
    ) {

        if (CmsPackageDto.CmsPackageTypeDto.DSC == cmsPackageDto.getType()) {
            SignedCertificateDto signedCertificateDto = getSignerCertificate(cmsPackageDto.getCms());
            if (!signedCertificateDto.isVerified()) {
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x260", "CMS signature is invalid", "",
                    "Submitted package needs to be signed by a valid upload certificate");
            }

            try {
                signerInformationService.updateSignerCertificate(cmsPackageDto.getEntityId(),
                    signedCertificateDto.getPayloadCertificate(), signedCertificateDto.getSignerCertificate(),
                    signedCertificateDto.getSignature(), countryCode);
            } catch (SignerInformationService.SignerCertCheckException e) {
                handleSignerCertException(cmsPackageDto, countryCode, e);
            }
        } else {
            SignedStringDto signedStringDto = getSignedString(cmsPackageDto.getCms());

            if (!signedStringDto.isVerified()) {
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x260", "CMS signature is invalid", "",
                    "Submitted package needs to be signed by a valid upload certificate");
            }
            try {
                if (CmsPackageDto.CmsPackageTypeDto.REVOCATION_LIST == cmsPackageDto.getType()) {
                    revocationListService.updateRevocationBatchCertificate(cmsPackageDto.getEntityId(),
                        signedStringDto.getPayloadString(), signedStringDto.getSignerCertificate(),
                        signedStringDto.getRawMessage(), countryCode);
                } else if (CmsPackageDto.CmsPackageTypeDto.VALIDATION_RULE == cmsPackageDto.getType()) {
                    validationRuleService.updateValidationRuleCertificate(cmsPackageDto.getEntityId(),
                        signedStringDto.getPayloadString(), signedStringDto.getSignerCertificate(),
                        signedStringDto.getRawMessage(), countryCode);
                }
            } catch (RevocationListService.RevocationBatchServiceException e) {
                handleRevocationBatchException(cmsPackageDto, countryCode, e);
            } catch (ValidationRuleService.ValidationRuleCheckException e) {
                handleValidationRuleExcepetion(cmsPackageDto, countryCode, e);
            }
        }

        return ResponseEntity.noContent().build();
    }

    private void updateMdc(String s, String message) {
        DgcMdc.put(MDC_VERIFICATION_ERROR_REASON, s);
        DgcMdc.put(MDC_VERIFICATION_ERROR_MESSAGE, message);
        log.error("CMS migration failed");
    }

    private void handleSignerCertException(CmsPackageDto cmsPackageDto, String countryCode,
                                           SignerInformationService.SignerCertCheckException e) {
        updateMdc(e.getReason().toString(), e.getMessage());
        String sentValues = String.format(SENT_VALUES_FORMAT, cmsPackageDto, countryCode);
        switch (e.getReason()) {
            case EXIST_CHECK_FAILED:
                throw new DgcgResponseException(HttpStatus.CONFLICT, "0x010",
                    "Certificate to be updated does not exist.",
                    sentValues, e.getMessage());
            case UPLOAD_FAILED:
                throw new DgcgResponseException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "0x011", "Upload of new Signer Certificate failed", sentValues, e.getMessage());
            default:
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, X_004, DEFAULT_ERROR_MESSAGE, sentValues,
                    e.getMessage());
        }
    }

    private void handleRevocationBatchException(CmsPackageDto cmsPackageDto, String countryCode,
                                                RevocationListService.RevocationBatchServiceException e) {
        updateMdc(e.getReason().toString(), e.getMessage());
        String sentValues = String.format(SENT_VALUES_FORMAT, cmsPackageDto, countryCode);
        switch (e.getReason()) {
            case NOT_FOUND:
                throw new DgcgResponseException(HttpStatus.CONFLICT, "0x020",
                    "RevocationBatch to be updated does not exist.",
                    sentValues, e.getMessage());
            case INVALID_COUNTRY:
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST,
                    "0x021", "Invalid country", sentValues, e.getMessage());
            case INVALID_JSON_VALUES:
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST,
                    "0x022", "Json Payload invalid", sentValues, e.getMessage());
            default:
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, X_004, DEFAULT_ERROR_MESSAGE, sentValues,
                    e.getMessage());
        }
    }

    private void handleValidationRuleExcepetion(CmsPackageDto cmsPackageDto, String countryCode,
                                                ValidationRuleService.ValidationRuleCheckException e) {
        updateMdc(e.getReason().toString(), e.getMessage());
        String sentValues = String.format(SENT_VALUES_FORMAT, cmsPackageDto, countryCode);
        switch (e.getReason()) {
            case NOT_FOUND:
                throw new DgcgResponseException(HttpStatus.CONFLICT, "0x030",
                    "ValidationRule to be updated does not exist.",
                    sentValues, e.getMessage());
            case INVALID_COUNTRY:
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST,
                    "0x031", "Invalid country", sentValues, e.getMessage());
            case INVALID_JSON:
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x032", "Json Payload invalid", sentValues,
                    e.getMessage());
            default:
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, X_004, DEFAULT_ERROR_MESSAGE, sentValues,
                    e.getMessage());
        }
    }
}
