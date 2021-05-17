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

import eu.europa.ec.dgc.gateway.model.TrustListType;
import eu.europa.ec.dgc.gateway.restapi.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustListDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.restapi.mapper.GwTrustListMapper;
import eu.europa.ec.dgc.gateway.service.TrustListService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import java.util.List;
import java.util.Locale;
import javax.validation.Valid;
import javax.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/trustList")
@RequiredArgsConstructor
@Validated
public class TrustListController {

    private final TrustListService trustListService;

    private final GwTrustListMapper trustListMapper;

    /**
     * TrustList Download Controller.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
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
    public ResponseEntity<List<TrustListDto>> downloadTrustList() {
        return ResponseEntity.ok(trustListMapper.trustListToTrustListDto(trustListService.getTrustList()));
    }

    /**
     * TrustList Download Controller (filtered by type).
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/{type}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
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
        @Valid @PathVariable("type") CertificateTypeDto type
    ) {

        TrustListType mappedType = trustListMapper.certificateTypeDtoToTrustListType(type);

        return ResponseEntity.ok(
            trustListMapper.trustListToTrustListDto(
                trustListService.getTrustList(mappedType)));
    }

    /**
     * TrustList Download Controller (filtered by type and country).
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/{type}/{country}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
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
        @Valid @Size(max = 2, min = 2) @PathVariable("country") String countryCode
    ) {

        TrustListType mappedType = trustListMapper.certificateTypeDtoToTrustListType(type);
        countryCode = countryCode.toUpperCase(Locale.ROOT);

        return ResponseEntity.ok(
            trustListMapper.trustListToTrustListDto(
                trustListService.getTrustList(mappedType, countryCode)));
    }

}
