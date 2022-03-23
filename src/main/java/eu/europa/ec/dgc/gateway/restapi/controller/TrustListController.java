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

package eu.europa.ec.dgc.gateway.restapi.controller;

import eu.europa.ec.dgc.gateway.config.OpenApiConfig;
import eu.europa.ec.dgc.gateway.model.TrustListType;
import eu.europa.ec.dgc.gateway.restapi.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustListDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedIssuerDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationFilter;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwTrustListMapper;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwTrustedIssuerMapper;
import eu.europa.ec.dgc.gateway.service.TrustListService;
import eu.europa.ec.dgc.gateway.service.TrustedIssuerService;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import javax.validation.Valid;
import javax.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/trustList")
@RequiredArgsConstructor
@Validated
@Slf4j
public class TrustListController {

    private final TrustListService trustListService;

    private final GwTrustListMapper trustListMapper;

    private final GwTrustedIssuerMapper trustedIssuerMapper;

    private final TrustedIssuerService trustedIssuerService;

    private static final String MDC_PROP_DOWNLOAD_KEYS_COUNT = "downloadedKeys";
    private static final String MDC_PROP_DOWNLOAD_KEYS_TYPE = "downloadedKeysType";
    private static final String MDC_PROP_DOWNLOAD_KEYS_COUNTRY = "downloadedKeysCountry";
    private static final String DOWNLOADED_TRUSTLIST_LOG_MESSAGE = "Downloaded TrustList";
    private static final DateTimeFormatter dateTimeFormatter =
        DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz");

    /**
     * TrustList Download Controller.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Returns the full list of trusted certificates.",
        tags = {"Trust Lists"},
        parameters = {
            @Parameter(
                in = ParameterIn.HEADER,
                name = HttpHeaders.IF_MODIFIED_SINCE,
                description = "Defines if only updated certificates since the given date should be returned.",
                required = false,
                schema = @Schema(implementation = String.class),
                example = "Wed, 21 Oct 2015 07:28:00 GMT"),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "page",
                description = "Page index, must NOT be negative.",
                required = false,
                schema = @Schema(implementation = Integer.class),
                example = "0"),
            @Parameter(
                in = ParameterIn.QUERY,
                description = "Number of certificates in a page to be returned, must be greater than 0.",
                required = false,
                schema = @Schema(implementation = Integer.class),
                example = "10")
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Returns the full list of trusted parties. Optional the download can be paginated"
                    + " and a delta download will be enabled by the header parameter 'If-Modified-Since'.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    array = @ArraySchema(schema = @Schema(implementation = TrustListDto.class)))),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. Invalid date in HTTP header 'If-Modified-Since'.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                )),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                ))
        })
    public ResponseEntity<List<TrustListDto>> downloadTrustList(
        @RequestHeader(value = HttpHeaders.IF_MODIFIED_SINCE, required = false) ZonedDateTime ifModifiedSince,
        @RequestParam(value = "page", required = false) Integer page,
        @RequestParam(value = "pagesize", required = false) Integer size,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String downloaderCountryCode
    ) {
        List<TrustListDto> trustList;
        if (isPaginationRequired(page,size)) {
            trustList = trustListMapper.trustListToTrustListDto(
                trustListService.getTrustList(ifModifiedDateTime, page, size));
        } else {
            trustList = trustListMapper.trustListToTrustListDto(
                trustListService.getTrustList(ifModifiedDateTime, null, null));
        }
        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_COUNT, trustList.size());
        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_COUNTRY, downloaderCountryCode);

        log.info(DOWNLOADED_TRUSTLIST_LOG_MESSAGE);

        return ResponseEntity.ok(trustList);
    }

    /**
     * TrustList Download Controller (filtered by type).
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/{type}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Returns a filtered list of trusted certificates.",
        tags = {"Trust Lists"},
        parameters = {
            @Parameter(
                in = ParameterIn.PATH,
                name = "type",
                description = "Certificate Type to filter for",
                required = true,
                schema = @Schema(implementation = CertificateTypeDto.class)),
            @Parameter(
                in = ParameterIn.HEADER,
                name = "If-Modified-Since",
                description = "Defines if only updated certificates since the given date should be returned.",
                required = false,
                schema = @Schema(implementation = String.class),
                example = "Wed, 21 Oct 2015 07:28:00 GMT"),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "page",
                description = "Page index, must NOT be negative.",
                required = false,
                schema = @Schema(implementation = Integer.class),
                example = "0"),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "pagesize",
                description = "Number of certificates in a page to be returned, must be greater than 0.",
                required = false,
                schema = @Schema(implementation = Integer.class),
                example = "10")
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Returns a filtered list of trusted certificates. Optional the download can be paginated"
                    + " and a delta download will be enabled by the header parameter 'If-Modified-Since'.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    array = @ArraySchema(schema = @Schema(implementation = TrustListDto.class)))),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. Unknown Certificate Type or invalid date in "
                    + "HTTP header 'If-Modified-Since'.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                )),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                ))
        })
    public ResponseEntity<List<TrustListDto>> downloadTrustListFilteredByType(
        @Valid @PathVariable("type") CertificateTypeDto type,
        @RequestHeader(value = IF_MODIFIED_SINCE_HEADER, required = false) String ifModifiedSince,
        @RequestParam(value = "page", required = false) Integer page,
        @RequestParam(value = "pagesize", required = false) Integer size,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String downloaderCountryCode
    ) {

        TrustListType mappedType = trustListMapper.certificateTypeDtoToTrustListType(type);
        List<TrustListDto> trustList;
        ZonedDateTime ifModifiedDateTime = null;
        if (ifModifiedSince != null) {
            try {
                ifModifiedDateTime = ZonedDateTime.parse(ifModifiedSince, dateTimeFormatter);
            } catch (DateTimeParseException e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }
        }
        if (isPaginationRequired(page,size)) {
            trustList = trustListMapper.trustListToTrustListDto(
                trustListService.getTrustList(mappedType, ifModifiedDateTime, page, size));
        } else {
            trustList = trustListMapper.trustListToTrustListDto(
                trustListService.getTrustList(mappedType, ifModifiedDateTime, null, null));
        }

        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_COUNT, trustList.size());
        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_TYPE, type.name());
        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_COUNTRY, downloaderCountryCode);

        log.info(DOWNLOADED_TRUSTLIST_LOG_MESSAGE);

        return ResponseEntity.ok(trustList);
    }

    /**
     * TrustList Download Controller (filtered by type and country).
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/{type}/{country}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Returns a filtered list of trusted certificates.",
        tags = {"Trust Lists"},
        parameters = {
            @Parameter(
                in = ParameterIn.PATH,
                name = "type",
                description = "Certificate Type to filter for",
                required = true,
                schema = @Schema(implementation = CertificateTypeDto.class)),
            @Parameter(
                in = ParameterIn.PATH,
                name = "country",
                description = "2-Digit Country Code to filter for",
                example = "EU",
                required = true),
            @Parameter(
                in = ParameterIn.HEADER,
                name = "If-Modified-Since",
                description = "Defines if only updated certificates since the given date should be returned.",
                required = false,
                schema = @Schema(implementation = String.class),
                example = "Wed, 21 Oct 2015 07:28:00 GMT"),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "page",
                description = "Page index, must NOT be negative.",
                required = false,
                schema = @Schema(implementation = Integer.class),
                example = "0"),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "pagesize",
                description = "Number of certificates in a page to be returned, must be greater than 0.",
                required = false,
                schema = @Schema(implementation = Integer.class),
                example = "10")
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Returns a filtered list of trusted certificates. Optional the download can be paginated"
                    + " and a delta download will be enabled by the header parameter 'If-Modified-Since'.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    array = @ArraySchema(schema = @Schema(implementation = TrustListDto.class)))),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. Unknown Certificate Type or invalid country code or "
                    + "invalid date in HTTP header 'If-Modified-Since'.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                )),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                ))
        })
    public ResponseEntity<List<TrustListDto>> downloadTrustListFilteredByCountryAndType(
        @Valid @PathVariable("type") CertificateTypeDto type,
        @Valid @Size(max = 2, min = 2) @PathVariable("country") String countryCode,
        @RequestHeader(value = IF_MODIFIED_SINCE_HEADER, required = false) String ifModifiedSince,
        @RequestParam(value = "page", required = false) Integer page,
        @RequestParam(value = "pagesize", required = false) Integer size,
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String downloaderCountryCode
    ) {

        TrustListType mappedType = trustListMapper.certificateTypeDtoToTrustListType(type);
        countryCode = countryCode.toUpperCase(Locale.ROOT);

        List<TrustListDto> trustList;
        ZonedDateTime ifModifiedDateTime = null;
        if (ifModifiedSince != null) {
            try {
                ifModifiedDateTime = ZonedDateTime.parse(ifModifiedSince, dateTimeFormatter);
            } catch (DateTimeParseException e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }
        }
        if (isPaginationRequired(page,size)) {
            trustList = trustListMapper.trustListToTrustListDto(
                trustListService.getTrustList(mappedType, countryCode, ifModifiedDateTime, page, size));
        } else {
            trustList = trustListMapper.trustListToTrustListDto(
                trustListService.getTrustList(mappedType, countryCode, ifModifiedDateTime, null, null));
        }

        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_COUNT, trustList.size());
        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_TYPE, type.name());
        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_COUNTRY, downloaderCountryCode);

        log.info(DOWNLOADED_TRUSTLIST_LOG_MESSAGE);

        return ResponseEntity.ok(trustList);
    }

    /**
     * TrustedIssuer TrustList Download.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/issuers", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            security = {
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
            },
            summary = "Returns the list of trusted issuers filtered by criterias.",
            tags = {"Trust List"},
            parameters = {
                    @Parameter(
                            in = ParameterIn.QUERY,
                            name = "country",
                            description = "Two-Digit Country Code",
                            examples = {@ExampleObject("EU"), @ExampleObject("DE")}
                    )
            },
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Returns the list of trusted issuers.",
                            content = @Content(
                                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                                    array = @ArraySchema(schema = @Schema(implementation = TrustedIssuerDto.class)))),
                    @ApiResponse(
                            responseCode = "401",
                            description = "Unauthorized. No Access to the system."
                                    + "(Client Certificate not present or whitelisted)",
                            content = @Content(
                                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                                    schema = @Schema(implementation = ProblemReportDto.class)
                            ))
            })
    public ResponseEntity<List<TrustedIssuerDto>> getTrustedIssuersByCountry(
            @RequestParam(value = "country", required = false) List<@Size(min = 2, max = 2) String> searchCountry
    ) {
        if (CollectionUtils.isNotEmpty(searchCountry)) {
            log.debug("Downloading TrustedIssuers TrustList. Parameters country: {}", searchCountry);
            return ResponseEntity.ok(trustedIssuerMapper.trustedIssuerEntityToTrustedIssuerDto(
                    trustedIssuerService.getAllIssuers(searchCountry)));
        } else {
            log.debug("Downloading all TrustedIssuers TrustList.");
            return ResponseEntity.ok(trustedIssuerMapper.trustedIssuerEntityToTrustedIssuerDto(
                    trustedIssuerService.getAllIssuers()));
        }
    }

    private boolean isPaginationRequired(Integer page, Integer size) {
        return page != null && size != null && page >= 0 && size > 0;
    }
}
