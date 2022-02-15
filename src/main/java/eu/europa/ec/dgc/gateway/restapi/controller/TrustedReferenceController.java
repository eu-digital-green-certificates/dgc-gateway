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
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.converter.CmsStringMessageConverter;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedStringDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationFilter;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwTrustedReferenceMapper;
import eu.europa.ec.dgc.gateway.service.TrustedReferenceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import java.util.List;
import javax.validation.Valid;
import javax.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/trust/reference")
@RequiredArgsConstructor
@Validated
@Slf4j
public class TrustedReferenceController {

    private final TrustedReferenceService trustedReferenceService;

    private final GwTrustedReferenceMapper trustedReferenceMapper;

    public static final String UUID_REGEX =
            "^[0-9a-f]{8}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{12}$";

    /**
     * Upload a new trusted reference.
     */
    @CertificateAuthenticationRequired
    @PostMapping(value = "", consumes = {
            CmsStringMessageConverter.CONTENT_TYPE_CMS_TEXT_VALUE, CmsStringMessageConverter.CONTENT_TYPE_CMS_VALUE})
    @Operation(
            security = {
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
            },
            tags = {"Trusted Reference"},
            summary = "Upload a new trusted reference",
            description = "Endpoint to upload a new trusted reference.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(schema = @Schema(implementation = TrustedReferenceDto.class))
            ),
            responses = {
                    @ApiResponse(
                            responseCode = "201",
                            description = "trusted reference created.")
            }
    )
    public ResponseEntity<Void> uploadTrustedReference(
            @RequestBody SignedStringDto batch,
            @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String countryCode) {

        if (!batch.isVerified()) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x260", "CMS signature is invalid", "",
                    "Submitted string needs to be signed by a valid upload certificate");
        }

        try {
            trustedReferenceService.addTrustedReference(
                    batch.getPayloadString(),
                    batch.getSignerCertificate(),
                    countryCode
            );
        } catch (TrustedReferenceService.TrustedReferenceServiceException e) {
            log.error("Upload of TrustedRefernece failed: {}, {}", e.getReason(), e.getMessage());

            switch (e.getReason()) {
                case INVALID_JSON:
                    throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x000", "JSON Could not be parsed", "",
                            e.getMessage());
                case INVALID_JSON_VALUES:
                    throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x000",
                            "Uploaded data has invalid values.", "", e.getMessage());
                case INVALID_COUNTRY:
                    throw new DgcgResponseException(HttpStatus.FORBIDDEN, "0x000", "Invalid Country sent", "",
                            e.getMessage());
                case UPLOADER_CERT_CHECK_FAILED:
                    throw new DgcgResponseException(HttpStatus.FORBIDDEN, "0x000", "Invalid Upload Certificate",
                            batch.getSignerCertificate().getSubject().toString(), "Certificate used to sign the batch "
                            + "is not a valid/ allowed upload certificate for your country.");
                default:
                    throw new DgcgResponseException(HttpStatus.INTERNAL_SERVER_ERROR, "0x000", "Unexpected Error",
                            "", "");
            }
        }

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * Get a lsit of all trusted references.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            security = {
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
            },
            tags = {"Trusted Reference"},
            summary = "Get a list of trusted references",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Response contains the trusted references list.",
                            content = @Content(schema = @Schema(implementation = TrustedReferenceDto.class))),
                    @ApiResponse(
                            responseCode = "204",
                            description = "No Content if no data is available.")
            }
    )
    public ResponseEntity<List<TrustedReferenceDto>> getTrustedReferences() {

        List<TrustedReferenceDto> trustedReferenceDtoList =
                trustedReferenceMapper.trustedReferenceEntityToTrustedReferenceDto(
                        trustedReferenceService.getAllReferences());

        if (trustedReferenceDtoList.isEmpty()) {
            return ResponseEntity.noContent().build();
        } else {
            return ResponseEntity.ok(trustedReferenceDtoList);
        }
    }

    /**
     * Get a single Trusted Reference.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/{uuid}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            security = {
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
            },
            tags = {"Trusted Reference"},
            summary = "Get a single trusted references",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Response contains the trusted reference.",
                            content = @Content(schema = @Schema(implementation = TrustedReferenceDto.class))),
                    @ApiResponse(
                            responseCode = "404",
                            description = "Not found if no data is available.")
            }
    )
    public ResponseEntity<TrustedReferenceDto> getTrustedReference(
            @Valid @PathVariable("uuid") @Pattern(regexp = UUID_REGEX) String uuid
    ) {

        try {
            TrustedReferenceDto trustedReferenceDto =
                    trustedReferenceMapper.trustedReferenceEntityToTrustedReferenceDto(
                            trustedReferenceService.getReference(uuid));

            return ResponseEntity.ok(trustedReferenceDto);
        } catch (TrustedReferenceService.TrustedReferenceServiceException e) {
            log.warn("Get of TrustedRefernece failed: {}, {}", e.getReason(), e.getMessage());
            if (e.getReason() == TrustedReferenceService.TrustedReferenceServiceException.Reason.NOT_FOUND) {
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x000",
                        "Requested Entity could not be found", "", e.getMessage());
            }
            throw new DgcgResponseException(HttpStatus.INTERNAL_SERVER_ERROR, "0x000", "Unexpected Error",
                    "", "");
        }
    }
}
