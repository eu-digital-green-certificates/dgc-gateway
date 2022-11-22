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
import eu.europa.ec.dgc.gateway.entity.RevocationBatchEntity;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.model.RevocationBatchDownload;
import eu.europa.ec.dgc.gateway.restapi.converter.CmsStringMessageConverter;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedStringDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationBatchDeleteRequestDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationBatchDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationBatchListDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationFilter;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRole;
import eu.europa.ec.dgc.gateway.restapi.mapper.RevocationBatchMapper;
import eu.europa.ec.dgc.gateway.service.RevocationListService;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import java.time.ZonedDateTime;
import javax.validation.Valid;
import javax.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/revocation-list")
@RequiredArgsConstructor
@Validated
@Slf4j
public class CertificateRevocationListController {

    private final RevocationListService revocationListService;

    private final RevocationBatchMapper revocationBatchMapper;

    public static final String UUID_REGEX =
        "^[0-9a-f]{8}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{12}$";

    private static final String MDC_DOWNLOADER_COUNTRY = "downloaderCountry";
    private static final String MDC_DOWNLOADED_COUNTRY = "downloadedCountry";
    private static final String MDC_DOWNLOADED_BATCH_ID = "downloadedBatchId";

    /**
     * Endpoint to download Revocation Batch List.
     */
    @CertificateAuthenticationRequired(requiredRoles = CertificateAuthenticationRole.RevocationListReader)
    @GetMapping(path = "", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        tags = {"Revocation"},
        summary = "Download Batch List",
        description = "Returning a list of batches with a small wrapper providing metadata."
            + " The batches are sorted by date in ascending (chronological) order.",
        parameters = {
            @Parameter(
                in = ParameterIn.HEADER,
                name = HttpHeaders.IF_MODIFIED_SINCE,
                description = "This header contains the last downloaded date to get just the latest results. "
                    + "On the initial call the header should be the set to ‘2021-06-01T00:00:00Z’",
                required = true)
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Response contains the batch list.",
                content = @Content(schema = @Schema(implementation = RevocationBatchListDto.class))),
            @ApiResponse(
                responseCode = "204",
                description = "No Content if no data is available later than provided If-Modified-Since header.")
        }
    )
    public ResponseEntity<RevocationBatchListDto> downloadBatchList(
        @Valid @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
        @RequestHeader(HttpHeaders.IF_MODIFIED_SINCE) ZonedDateTime ifModifiedSince) {

        if (ifModifiedSince.isAfter(ZonedDateTime.now())) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "", "IfModifiedSince must be in past", "", "");
        }

        RevocationBatchListDto revocationBatchListDto =
            revocationBatchMapper.toDto(revocationListService.getRevocationBatchList(ifModifiedSince));

        if (revocationBatchListDto.getBatches().isEmpty()) {
            return ResponseEntity.noContent().build();
        } else {
            return ResponseEntity.ok(revocationBatchListDto);
        }
    }

    /**
     * Endpoint to download Revocation Batch.
     */
    @CertificateAuthenticationRequired(requiredRoles = CertificateAuthenticationRole.RevocationListReader)
    @GetMapping(value = "/{batchId}", produces = {
        CmsStringMessageConverter.CONTENT_TYPE_CMS_TEXT_VALUE, CmsStringMessageConverter.CONTENT_TYPE_CMS_VALUE})
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        tags = {"Revocation"},
        summary = "Download Batch",
        description = "Returning a batch with hashes of revoked certificates by its Batch ID.",
        parameters = {
            @Parameter(
                in = ParameterIn.PATH,
                name = "batchId",
                description = "ID of the batch to download",
                schema = @Schema(implementation = String.class, format = "UUID", pattern = UUID_REGEX),
                required = true)
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Response contains the batch.",
                content = @Content(schema = @Schema(implementation = RevocationBatchDto.class)),
                headers = @Header(name = HttpHeaders.ETAG, description = "Batch ID")),
            @ApiResponse(
                responseCode = "404",
                description = "Batch does not exist."),
            @ApiResponse(
                responseCode = "410",
                description = "Batch already deleted.")
        }
    )
    public ResponseEntity<String> downloadBatch(
        @Valid @PathVariable("batchId") @Pattern(regexp = UUID_REGEX) String batchId,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String downloaderCountry) {

        try {
            RevocationBatchDownload download = revocationListService.getRevocationBatch(batchId);


            DgcMdc.put(MDC_DOWNLOADED_COUNTRY, download.getCountry());
            DgcMdc.put(MDC_DOWNLOADER_COUNTRY, downloaderCountry);
            DgcMdc.put(MDC_DOWNLOADED_BATCH_ID, batchId);

            log.info("Revocation Batch downloaded.");

            return ResponseEntity
                .ok()
                .header(HttpHeaders.ETAG, download.getBatchId())
                .body(download.getSignedCms());

        } catch (RevocationListService.RevocationBatchServiceException e) {
            switch (e.getReason()) {
                case GONE:
                    throw new DgcgResponseException(HttpStatus.GONE, "0x000", "Batch already deleted.", "",
                        e.getMessage());
                case NOT_FOUND:
                    throw new DgcgResponseException(HttpStatus.NOT_FOUND, "0x000", "Batch does not exist.", "",
                        e.getMessage());
                default:
                    throw new DgcgResponseException(HttpStatus.INTERNAL_SERVER_ERROR, "0x000", "Unexpected Error",
                        "", "");

            }
        }
    }

    /**
     * Endpoint to upload Revocation Batch.
     */
    @CertificateAuthenticationRequired(requiredRoles = CertificateAuthenticationRole.RevocationUploader)
    @PostMapping(value = "", consumes = {
        CmsStringMessageConverter.CONTENT_TYPE_CMS_TEXT_VALUE, CmsStringMessageConverter.CONTENT_TYPE_CMS_VALUE})
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        tags = {"Revocation"},
        summary = "Upload a new Batch",
        description = "Endpoint to upload a new Batch of certificate hashes for revocation.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            content = @Content(schema = @Schema(implementation = RevocationBatchDto.class))
        ),
        responses = {
            @ApiResponse(
                responseCode = "201",
                description = "Batch created.",
                headers = @Header(name = HttpHeaders.ETAG, description = "Batch ID of created Batch")),
            @ApiResponse(
                responseCode = "409",
                description = "Batch already exists.")
        }
    )
    public ResponseEntity<Void> uploadBatch(
        @RequestBody SignedStringDto batch,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String countryCode) {

        if (!batch.isVerified()) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x260", "CMS signature is invalid", "",
                "Submitted string needs to be signed by a valid upload certificate");
        }

        String batchId;

        try {
            RevocationBatchEntity entity = revocationListService.addRevocationBatch(
                batch.getPayloadString(),
                batch.getSignerCertificate(),
                batch.getRawMessage(),
                countryCode
            );

            batchId = entity.getBatchId();
        } catch (RevocationListService.RevocationBatchServiceException e) {
            log.error("Upload of Revocation Batch failed: {}, {}", e.getReason(), e.getMessage());

            switch (e.getReason()) {
                case INVALID_JSON:
                    throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x000", "JSON Could not be parsed", "",
                        e.getMessage());
                case INVALID_JSON_VALUES:
                    throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x000", "Batch has invalid values.", "",
                        e.getMessage());
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

        return ResponseEntity
            .status(HttpStatus.CREATED)
            .header(HttpHeaders.ETAG, batchId)
            .build();
    }

    /**
     * Endpoint to delete Revocation Batch.
     */
    @CertificateAuthenticationRequired(requiredRoles = CertificateAuthenticationRole.RevocationDeleter)
    @DeleteMapping(value = "", consumes = {
        CmsStringMessageConverter.CONTENT_TYPE_CMS_TEXT_VALUE, CmsStringMessageConverter.CONTENT_TYPE_CMS_VALUE})
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        tags = {"Revocation"},
        summary = "Delete a Batch",
        description = "Deletes a batch of hashes for certificate revocation. "
            + "Batch will be marked as Deleted and deletion will follow up within 7 days.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            description = "The Batch ID as signed CMS.",
            content = @Content(schema = @Schema(implementation = RevocationBatchDeleteRequestDto.class))
        ),
        responses = {
            @ApiResponse(
                responseCode = "204",
                description = "Batch deleted."),
            @ApiResponse(
                responseCode = "404",
                description = "Batch does not exist.")
        }
    )
    public ResponseEntity<Void> deleteBatch(
        @RequestBody SignedStringDto batchDeleteRequest,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String countryCode) {

        if (!batchDeleteRequest.isVerified()) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x260", "CMS signature is invalid", "",
                "Submitted string needs to be signed by a valid upload certificate");
        }

        try {
            revocationListService.deleteRevocationBatch(
                batchDeleteRequest.getPayloadString(),
                batchDeleteRequest.getSignerCertificate(),
                countryCode);
        } catch (RevocationListService.RevocationBatchServiceException e) {
            switch (e.getReason()) {
                case INVALID_JSON:
                    throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x000", "JSON Could not be parsed", "",
                        e.getMessage());
                case INVALID_JSON_VALUES:
                    throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x000",
                        "Delete Request has invalid values.", "",
                        e.getMessage());
                case INVALID_COUNTRY:
                    throw new DgcgResponseException(HttpStatus.FORBIDDEN, "0x000", "Invalid Country sent", "",
                        e.getMessage());
                case NOT_FOUND:
                    throw new DgcgResponseException(HttpStatus.NOT_FOUND, "0x000", "Batch does not exists.", "",
                        e.getMessage());
                case GONE:
                    throw new DgcgResponseException(HttpStatus.GONE, "0x000", "Batch is already deleted.", "",
                        e.getMessage());
                case UPLOADER_CERT_CHECK_FAILED:
                    throw new DgcgResponseException(HttpStatus.FORBIDDEN, "0x000", "Invalid Upload Certificate",
                        batchDeleteRequest.getSignerCertificate().getSubject().toString(),
                        "Certificate used to sign the batch is not a valid/ allowed"
                            + " upload certificate for your country.");
                default:
                    throw new DgcgResponseException(HttpStatus.INTERNAL_SERVER_ERROR, "0x000", "Unexpected Error",
                        "", "");
            }
        }

        return ResponseEntity.noContent().build();
    }

    /**
     * Alternative endpoint to delete revocation batches.
     */
    @CertificateAuthenticationRequired(requiredRoles = CertificateAuthenticationRole.RevocationDeleter)
    @PostMapping(value = "/delete", consumes = {
        CmsStringMessageConverter.CONTENT_TYPE_CMS_TEXT_VALUE, CmsStringMessageConverter.CONTENT_TYPE_CMS_VALUE})
    public ResponseEntity<Void> deleteBatchAlternativeEndpoint(
        @RequestBody SignedStringDto batchDeleteRequest,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String countryCode) {

        return deleteBatch(batchDeleteRequest, countryCode);
    }
}
