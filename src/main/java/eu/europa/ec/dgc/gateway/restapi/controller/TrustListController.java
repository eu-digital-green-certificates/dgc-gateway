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

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.config.OpenApiConfig;
import eu.europa.ec.dgc.gateway.model.TrustListType;
import eu.europa.ec.dgc.gateway.restapi.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustListDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedCertificateTrustListDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedIssuerDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedIssuerDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationFilter;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwTrustListMapper;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwTrustedIssuerMapper;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwTrustedReferenceMapper;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwTrustedIssuerMapper;
import eu.europa.ec.dgc.gateway.service.TrustListService;
import eu.europa.ec.dgc.gateway.service.TrustedIssuerService;
import eu.europa.ec.dgc.gateway.service.TrustedReferenceService;
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
import java.util.List;
import java.util.Locale;
import javax.validation.Valid;
import javax.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
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

    private final ObjectMapper objectMapper;

    private final GwTrustedIssuerMapper trustedIssuerMapper;

    private final TrustedIssuerService trustedIssuerService;

    private final GwTrustedReferenceMapper trustedReferenceMapper;

    private final TrustedReferenceService trustedReferenceService;

    private static final String MDC_PROP_DOWNLOAD_KEYS_COUNT = "downloadedKeys";
    private static final String MDC_PROP_DOWNLOAD_KEYS_TYPE = "downloadedKeysType";
    private static final String MDC_PROP_DOWNLOAD_KEYS_COUNTRY = "downloadedKeysCountry";
    private static final String DOWNLOADED_TRUSTLIST_LOG_MESSAGE = "Downloaded TrustList";

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
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Returns the full list of trusted parties.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    array = @ArraySchema(schema = @Schema(implementation = TrustListDto.class)))),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                ))
        })
    public ResponseEntity<List<TrustListDto>> downloadTrustList(
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String downloaderCountryCode
    ) {
        List<TrustListDto> trustList = trustListMapper.trustListToTrustListDto(trustListService.getTrustList());

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
                schema = @Schema(implementation = CertificateTypeDto.class))
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Returns a filtered list of trusted certificates.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    array = @ArraySchema(schema = @Schema(implementation = TrustListDto.class)))),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. Unknown Certificate Type.",
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
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String downloaderCountryCode
    ) {

        TrustListType mappedType = trustListMapper.certificateTypeDtoToTrustListType(type);

        List<TrustListDto> trustList = trustListMapper.trustListToTrustListDto(
            trustListService.getTrustList(mappedType));

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
                required = true)
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Returns a filtered list of trusted certificates.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    array = @ArraySchema(schema = @Schema(implementation = TrustListDto.class)))),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. Unknown Certificate Type or invalid country code.",
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
        @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String downloaderCountryCode
    ) {

        TrustListType mappedType = trustListMapper.certificateTypeDtoToTrustListType(type);
        countryCode = countryCode.toUpperCase(Locale.ROOT);

        List<TrustListDto> trustList = trustListMapper.trustListToTrustListDto(
            trustListService.getTrustList(mappedType, countryCode));

        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_COUNT, trustList.size());
        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_TYPE, type.name());
        DgcMdc.put(MDC_PROP_DOWNLOAD_KEYS_COUNTRY, downloaderCountryCode);

        log.info(DOWNLOADED_TRUSTLIST_LOG_MESSAGE);

        return ResponseEntity.ok(trustList);
    }

    /**
     * TrustList Download Controller (filtered by type).
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/certificate", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Returns a filtered list of trusted certificates. The provided search criteria are additive."
            + " It is possible to provide more than one value for each criteria. (Except for withFederation)",
        tags = {"Trust Lists"},
        parameters = {
            @Parameter(
                in = ParameterIn.QUERY,
                name = "group",
                description = "Value for Group to search for",
                examples = {@ExampleObject("AUTHENTICATION"), @ExampleObject("AUTHENTICATION_FEDERATION"),
                    @ExampleObject("UPLOAD"), @ExampleObject("CSCA"), @ExampleObject("TRUSTANCHOR"),
                    @ExampleObject("DSC"), @ExampleObject("SIGN"), @ExampleObject("AUTH"), @ExampleObject("CUSTOM")}
            ),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "country",
                description = "Two-Digit Country Code",
                examples = {@ExampleObject("EU"), @ExampleObject("DE")}
            ),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "domain",
                description = "Value for Domain to search for",
                examples = {@ExampleObject("DCC"), @ExampleObject("ICAO")}
            ),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "withFederation",
                description = "Switch if federated entities should be included",
                allowEmptyValue = true,
                schema = @Schema(implementation = Boolean.class)
            )
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Returns a filtered list of trusted certificates.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    array = @ArraySchema(schema = @Schema(implementation = TrustListDto.class)))),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. Unknown Certificate Type.",
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
    public ResponseEntity<List<TrustedCertificateTrustListDto>> downloadTrustListCertificate(
        @RequestParam(value = "group", required = false) List<String> searchGroup,
        @RequestParam(value = "country", required = false) List<String> searchCountry,
        @RequestParam(value = "domain", required = false) List<String> searchDomain,
        @RequestParam(value = "withFederation", required = false) Boolean withFederation
    ) {
        log.debug("Downloading TrustedCertificate TrustList. Parameters group: {}, country: {}, domain: {}, "
            + "withFederation: {}", searchGroup, searchCountry, searchDomain, withFederation);

        return ResponseEntity.ok(trustListMapper.trustListToDto(trustListService.getTrustedCertificateTrustList(
            searchGroup,
            searchCountry,
            searchDomain,
            Boolean.TRUE.equals(withFederation)), objectMapper));
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
            ),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "domain",
                description = "Value for Domain to search for",
                examples = {@ExampleObject("DCC"), @ExampleObject("ICAO")}
            ),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "withFederation",
                description = "Switch if federated entities should be included",
                allowEmptyValue = true,
                schema = @Schema(implementation = Boolean.class)
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
        @RequestParam(value = "country", required = false) List<String> searchCountry,
        @RequestParam(value = "domain", required = false) List<String> searchDomain,
        @RequestParam(value = "withFederation", required = false) Boolean withFederation
    ) {
        log.debug("Downloading TrustedIssuers TrustList. Parameters country: {}, domain: {}, "
            + "withFederation: {}", searchCountry, searchDomain, withFederation);

        return ResponseEntity.ok(trustedIssuerMapper.trustedIssuerEntityToTrustedIssuerDto(
            trustedIssuerService.search(searchDomain, searchCountry, Boolean.TRUE.equals(withFederation))));
    }

    /**
     * TrustedReference TrustList Download.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/references", produces = MediaType.APPLICATION_JSON_VALUE)
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
            ),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "domain",
                description = "Value for Domain to search for",
                examples = {@ExampleObject("DCC"), @ExampleObject("ICAO")}
            ),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "referenceType",
                description = "Value for Reference Type to search for",
                examples = {@ExampleObject("DCC"), @ExampleObject("FHIR")}
            ),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "signatureType",
                description = "Value for Signature Type to search for",
                examples = {@ExampleObject("CMS"), @ExampleObject("JWS"), @ExampleObject("NONE")}
            ),
            @Parameter(
                in = ParameterIn.QUERY,
                name = "withFederation",
                description = "Switch if federated entities should be included",
                allowEmptyValue = true,
                schema = @Schema(implementation = Boolean.class)
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
    public ResponseEntity<List<TrustedReferenceDto>> getTrustedReferencesTrustList(
        @RequestParam(value = "country", required = false) List<String> searchCountry,
        @RequestParam(value = "domain", required = false) List<String> searchDomain,
        @RequestParam(value = "referenceType", required = false) List<String> searchReferenceType,
        @RequestParam(value = "signatureType", required = false) List<String> searchSignatureType,
        @RequestParam(value = "withFederation", required = false) Boolean withFederation
    ) {
        log.debug("Downloading TrustedReferences TrustList. Parameters country: {}, domain: {}, "
            + "withFederation: {}", searchCountry, searchDomain, withFederation);

        return ResponseEntity.ok(trustedReferenceMapper.trustedReferenceEntityToTrustedReferenceDto(
            trustedReferenceService.search(searchDomain, searchCountry, searchReferenceType, searchSignatureType,
                Boolean.TRUE.equals(withFederation))));
    }

}
