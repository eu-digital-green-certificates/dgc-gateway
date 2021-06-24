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

package eu.europa.ec.dgc.gateway.restapi.controller;

import eu.europa.ec.dgc.gateway.config.OpenApiConfig;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.converter.CmsCertificateMessageConverter;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedCertificateDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationFilter;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.service.AuditService;
import eu.europa.ec.dgc.gateway.service.SignerInformationService;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/signerCertificate")
@Slf4j
@RequiredArgsConstructor
public class SignerCertificateController {

    private final SignerInformationService signerInformationService;

    private final AuditService auditService;

    private static final String MDC_VERIFICATION_ERROR_REASON = "verificationFailureReason";
    private static final String MDC_VERIFICATION_ERROR_MESSAGE = "verificationFailureMessage";

    /**
     * VerificationInformation Upload Controller.
     */
    @CertificateAuthenticationRequired
    @PostMapping(path = "", consumes = CmsCertificateMessageConverter.CONTENT_TYPE_CMS_VALUE)
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Uploads Signer Certificate of a trusted Issuer",
        tags = {"Signer Information"},
        parameters = {
            @Parameter(
                in = ParameterIn.HEADER,
                name = HttpHeaders.CONTENT_TYPE,
                required = true,
                schema = @Schema(type = "string"),
                example = CmsCertificateMessageConverter.CONTENT_TYPE_CMS_VALUE),
            @Parameter(
                in = ParameterIn.HEADER,
                name = HttpHeaders.CONTENT_ENCODING,
                required = true,
                schema = @Schema(type = "string"),
                example = "base64")
        },
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            description = "Request body with payload. (limited)",
            content = @Content(
                mediaType = CmsCertificateMessageConverter.CONTENT_TYPE_CMS_VALUE,
                schema = @Schema(implementation = SignedCertificateDto.class))
        ),
        responses = {
            @ApiResponse(
                responseCode = "201",
                description = "Verification Information was created successfully."),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. Possible reasons: Wrong Format, no CMS, not the correct signing alg,"
                    + " missing attributes, invalid signature, certificate not signed by known CA",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                )),
            @ApiResponse(
                responseCode = "409",
                description = "Conflict. Chosen UUID is already used. Please choose another one.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)))
        }
    )
    public ResponseEntity<Void> postVerificationInformation(
        @RequestBody SignedCertificateDto cms,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String countryCode,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT) String authThumbprint
    ) {

        DgcMdc.put("signerCertSubject", cms.getSignerCertificate().getSubject().toString());
        DgcMdc.put("payloadCertSubject", cms.getPayloadCertificate().getSubject().toString());

        log.info("Uploading new verification certificate");

        if (!cms.isVerified()) {
            throw new DgcgResponseException(
                HttpStatus.BAD_REQUEST,
                "0x009",
                "Invalid CMS Signature",
                "",
                "Signature of CMS signed certificate is not validating content of CMS package");
        }

        try {
            signerInformationService.addSignerCertificate(
                cms.getPayloadCertificate(),
                cms.getSignerCertificate(),
                cms.getSignature(),
                countryCode);
        } catch (SignerInformationService.SignerCertCheckException e) {
            DgcMdc.put(MDC_VERIFICATION_ERROR_REASON, e.getReason().toString());
            DgcMdc.put(MDC_VERIFICATION_ERROR_MESSAGE, e.getMessage());
            log.error("Verification certificate upload failed");

            String sentValues = String.format("{%s} country:{%s}", cms, countryCode);
            if (e.getReason() == SignerInformationService.SignerCertCheckException.Reason.ALREADY_EXIST_CHECK_FAILED) {
                throw new DgcgResponseException(HttpStatus.CONFLICT, "0x002",
                    "You cant upload an existing certificate.",
                    sentValues, e.getMessage());
            } else if (e.getReason() == SignerInformationService.SignerCertCheckException.Reason.UPLOAD_FAILED) {
                auditService.addAuditEvent(
                    countryCode,
                    cms.getSignerCertificate(),
                    authThumbprint,
                    "UPLOAD_FAILED",
                    "postVerificationInformation triggered UPLOAD_FAILED");

                throw new DgcgResponseException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "0x003", "Upload of Signer Certificate failed", sentValues, e.getMessage());
            } else {
                auditService.addAuditEvent(
                    countryCode,
                    cms.getSignerCertificate(),
                    authThumbprint,
                    "BAD_REQUEST",
                    "postVerificationInformation triggered BAD_REQUEST");

                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x004", "Possible reasons: Wrong Format,"
                    + " no CMS, not the correct signing alg missing attributes, invalid signature, certificate not "
                    + "signed by known CA", sentValues, e.getMessage());
            }
        }
        auditService.addAuditEvent(
            countryCode,
            cms.getSignerCertificate(),
            authThumbprint,
            "SUCCESS",
            "postVerificationInformation successful executed");
        return ResponseEntity.status(201).build();
    }

    /**
     * Http Method for deleting signer certificate.
     */
    @CertificateAuthenticationRequired
    @DeleteMapping(path = "", consumes = CmsCertificateMessageConverter.CONTENT_TYPE_CMS_VALUE)
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Deletes Signer Certificate of a trusted Issuer",
        tags = {"Signer Information"},
        parameters = {
            @Parameter(
                in = ParameterIn.HEADER,
                name = HttpHeaders.CONTENT_TYPE,
                required = true,
                schema = @Schema(type = "string"),
                example = CmsCertificateMessageConverter.CONTENT_TYPE_CMS_VALUE),
            @Parameter(
                in = ParameterIn.HEADER,
                name = HttpHeaders.CONTENT_ENCODING,
                required = true,
                schema = @Schema(type = "string"),
                example = "base64")
        },
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            description = "Request body with payload. (limited)",
            content = @Content(
                mediaType = CmsCertificateMessageConverter.CONTENT_TYPE_CMS_VALUE,
                schema = @Schema(implementation = SignedCertificateDto.class))
        ),
        responses = {
            @ApiResponse(
                responseCode = "204",
                description = "Certificate was deleted successfully."),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. Possible reasons: Wrong Format, no CMS, not the correct signing alg,"
                    + " missing attributes, invalid signature, certificate not signed by known CA",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                ))
        }
    )
    public ResponseEntity<Void> deleteVerificationInformation(
        @RequestBody SignedCertificateDto cms,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String countryCode,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT) String authThumbprint
    ) {

        DgcMdc.put("signerCertSubject", cms.getSignerCertificate().getSubject().toString());
        DgcMdc.put("payloadCertSubject", cms.getPayloadCertificate().getSubject().toString());

        log.info("Revoking verification certificate");

        if (!cms.isVerified()) {
            throw new DgcgResponseException(
                HttpStatus.BAD_REQUEST,
                "0x009",
                "Invalid CMS Signature",
                "",
                "Signature of CMS signed certificate is not validating content of CMS package");
        }

        try {
            signerInformationService.deleteSignerCertificate(
                cms.getPayloadCertificate(),
                cms.getSignerCertificate(),
                countryCode);
        } catch (SignerInformationService.SignerCertCheckException e) {
            DgcMdc.put(MDC_VERIFICATION_ERROR_REASON, e.getReason().toString());
            DgcMdc.put(MDC_VERIFICATION_ERROR_MESSAGE, e.getMessage());
            log.error("Verification certificate delete failed");

            String sentValues = String.format("{%s} country:{%s}", cms, countryCode);
            if (e.getReason() == SignerInformationService.SignerCertCheckException.Reason.EXIST_CHECK_FAILED) {
                auditService.addAuditEvent(
                    countryCode,
                    cms.getSignerCertificate(),
                    authThumbprint,
                    "EXIST_CHECK_FAILED",
                    "revokeVerificationInformation triggered EXIST_CHECK_FAILED");

                throw new DgcgResponseException(HttpStatus.NOT_FOUND, "0x005",
                    "The certificate doesn't exists in the database.",
                    sentValues, e.getMessage());
            } else if (e.getReason() == SignerInformationService.SignerCertCheckException.Reason.UPLOAD_FAILED) {
                auditService.addAuditEvent(
                    countryCode,
                    cms.getSignerCertificate(),
                    authThumbprint,
                    "DELETE_FAILED",
                    "revokeVerificationInformation triggered UPLOAD_FAILED");

                throw new DgcgResponseException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "0x006", "Delete of Signer Certificate failed", sentValues, e.getMessage());
            } else {
                auditService.addAuditEvent(
                    countryCode,
                    cms.getSignerCertificate(),
                    authThumbprint,
                    "BAD_REQUEST",
                    "revokeVerificationInformation triggered BAD_REQUEST");

                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x007", "Possible reasons: Wrong Format,"
                    + " no CMS, not the correct signing alg missing attributes, invalid signature, certificate not "
                    + "signed by known CA", sentValues, e.getMessage());
            }
        }
        auditService.addAuditEvent(
            countryCode,
            cms.getSignerCertificate(),
            authThumbprint,
            "SUCCESS",
            "revokeVerificationInformation triggered SUCCESS");

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    /**
     * Alias Method for deleting signer certificate.
     */
    @CertificateAuthenticationRequired
    @PostMapping(path = "/delete", consumes = CmsCertificateMessageConverter.CONTENT_TYPE_CMS_VALUE)
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Deletes Signer Certificate of a trusted Issuer",
        description = "This endpoint is a workaround alias endpoint. This should only be used if it is not possible"
            + " to send http payloads with DELETE requests.",
        tags = {"Signer Information"},
        parameters = {
            @Parameter(
                in = ParameterIn.HEADER,
                name = HttpHeaders.CONTENT_TYPE,
                required = true,
                schema = @Schema(type = "string"),
                example = CmsCertificateMessageConverter.CONTENT_TYPE_CMS_VALUE),
            @Parameter(
                in = ParameterIn.HEADER,
                name = HttpHeaders.CONTENT_ENCODING,
                required = true,
                schema = @Schema(type = "string"),
                example = "base64")
        },
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            description = "Request body with payload. (limited)",
            content = @Content(
                mediaType = CmsCertificateMessageConverter.CONTENT_TYPE_CMS_VALUE,
                schema = @Schema(implementation = SignedCertificateDto.class))
        ),
        responses = {
            @ApiResponse(
                responseCode = "204",
                description = "Certificate was deleted successfully."),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. Possible reasons: Wrong Format, no CMS, not the correct signing alg,"
                    + " missing attributes, invalid signature, certificate not signed by known CA",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                ))
        }
    )
    public ResponseEntity<Void> deleteVerificationInformationAlias(
        @RequestBody SignedCertificateDto cms,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String countryCode,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT) String authThumbprint
    ) {
        return deleteVerificationInformation(cms, countryCode, authThumbprint);
    }
}
