package eu.europa.ec.dgc.gateway.restapi.controller;

import eu.europa.ec.dgc.gateway.config.OpenApiConfig;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedIssuerDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationFilter;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwTrustedIssuerMapper;
import eu.europa.ec.dgc.gateway.service.TrustedIssuerService;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/trust/issuers")
@RequiredArgsConstructor
@Validated
@Slf4j
public class TrustedIssuerController {


    private final TrustedIssuerService trustedIssuerService;

    private final GwTrustedIssuerMapper trustedIssuerMapper;

    private static final String MDC_PROP_DOWNLOAD_ISSUERS_COUNT = "downloadedIssuers";
    private static final String MDC_PROP_DOWNLOAD_ISSUERS_COUNTRY = "downloadedIssuersCountry";

    /**
     * TrustedIssuer List all issuers.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            security = {
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
            },
            summary = "Returns the full list of trusted issuers.",
            tags = {"Trusted Issuer"},
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Returns the full list of trusted issuers.",
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
    public ResponseEntity<List<TrustedIssuerDto>> getTrustedIssuers(
            @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String downloaderCountryCode
    ) {
        List<TrustedIssuerDto> trustedIssuers =
                trustedIssuerMapper.trustedIssuerEntityToTrustedIssuerDto(trustedIssuerService.getAllIssuers());

        DgcMdc.put(MDC_PROP_DOWNLOAD_ISSUERS_COUNT, trustedIssuers.size());
        DgcMdc.put(MDC_PROP_DOWNLOAD_ISSUERS_COUNTRY, downloaderCountryCode);

        return ResponseEntity.ok(trustedIssuers);
    }

    /**
     * TrustedIssuer List all issuers by country.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/{country}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            security = {
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
                    @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
            },
            summary = "Returns the list of trusted issuers by country.",
            tags = {"Trusted Issuer"},
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Returns the list of trusted issuers by country.",
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
            @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY) String downloaderCountryCode,
            @PathVariable("country") String requestedCountry
    ) {
        List<TrustedIssuerDto> trustedIssuers =
                trustedIssuerMapper.trustedIssuerEntityToTrustedIssuerDto(
                        trustedIssuerService.getAllIssuers(requestedCountry));

        DgcMdc.put(MDC_PROP_DOWNLOAD_ISSUERS_COUNT, trustedIssuers.size());
        DgcMdc.put(MDC_PROP_DOWNLOAD_ISSUERS_COUNTRY, downloaderCountryCode);

        return ResponseEntity.ok(trustedIssuers);
    }
}
