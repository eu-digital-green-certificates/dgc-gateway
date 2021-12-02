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
import eu.europa.ec.dgc.gateway.restapi.converter.CmsStringMessageConverter;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedStringDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.BatchDeleteRequestDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.BatchDto;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.BatchListDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/crl")
@RequiredArgsConstructor
@Validated
@Slf4j
public class CertificateRevocationListController {

    public static final String UUID_REGEX =
        "^[0-9a-f]{8}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{12}$";

    /**
     * Endpoint to download Revocation Batch List.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "", produces = {
        CmsStringMessageConverter.CONTENT_TYPE_CMS_TEXT_VALUE, CmsStringMessageConverter.CONTENT_TYPE_CMS_VALUE})
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
                content = @Content(schema = @Schema(implementation = BatchListDto.class))),
            @ApiResponse(
                responseCode = "204",
                description = "No Content if no data is available later than provided If-Modified-Since header.")
        }
    )
    public ResponseEntity<BatchListDto> downloadBatchList(
        @Valid @RequestHeader(HttpHeaders.IF_MODIFIED_SINCE) ZonedDateTime ifModifiedSince) {

        return ResponseEntity.ok().build();
    }

    /**
     * Endpoint to download Revocation Batch.
     */
    @CertificateAuthenticationRequired
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
                content = @Content(schema = @Schema(implementation = BatchDto.class)),
                headers = @Header(name = HttpHeaders.ETAG, description = "Batch ID")),
            @ApiResponse(
                responseCode = "404",
                description = "Batch does not exist."),
            @ApiResponse(
                responseCode = "410",
                description = "Batch already deleted.")
        }
    )
    public ResponseEntity<BatchDto> downloadBatch(
        @Valid @PathVariable("batchId") @Pattern(regexp = UUID_REGEX) String batchId) {

        return ResponseEntity.ok().build();
    }

    /**
     * Endpoint to upload Revocation Batch.
     */
    @CertificateAuthenticationRequired
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
            content = @Content(schema = @Schema(implementation = BatchDto.class))
        ),
        responses = {
            @ApiResponse(
                responseCode = "201",
                description = "Batch created."),
            @ApiResponse(
                responseCode = "409",
                description = "Batch already exists.")
        }
    )
    public ResponseEntity<Void> uploadBatch(@Valid @RequestBody SignedStringDto batch) {

        return ResponseEntity.ok().build();
    }

    /**
     * Endpoint to delete Revocation Batch.
     */
    @CertificateAuthenticationRequired
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
            content = @Content(schema = @Schema(implementation = BatchDeleteRequestDto.class))
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
        @Valid @Pattern(regexp = UUID_REGEX) @RequestBody SignedStringDto batchDeleteRequest) {

        return ResponseEntity.ok().build();
    }

    /**
     * Alternative endpoint to delete recovation batches.
     */
    @PostMapping(value = "/delete", consumes = {
        CmsStringMessageConverter.CONTENT_TYPE_CMS_TEXT_VALUE, CmsStringMessageConverter.CONTENT_TYPE_CMS_VALUE})
    public ResponseEntity<Void> deleteBatchAlternativeEndpoint(
        @Valid @Pattern(regexp = UUID_REGEX) @RequestBody SignedStringDto batchDeleteRequest) {

        return deleteBatch(batchDeleteRequest);
    }
}
