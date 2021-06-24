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
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.service.ValuesetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/valuesets")
@Slf4j
@RequiredArgsConstructor
public class ValuesetController {

    private final ValuesetService valuesetService;

    /**
     * Controller to get valueset ids.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "")
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Gets a list of available valuesets.",
        tags = {"Valueset"},
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "List of valueset ids",
                content = @Content(array = @ArraySchema(schema = @Schema(implementation = String.class)))
            ),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                ))
        }
    )
    public ResponseEntity<List<String>> getValuesetIds() {
        return ResponseEntity.ok(valuesetService.getValuesetIds());
    }
    
    /**
     * Controller to get a specific valueset.
     */
    @CertificateAuthenticationRequired
    @GetMapping(path = "/{id}")
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Requests a specific valueset by its id.",
        tags = {"Valueset"},
        parameters = @Parameter(in = ParameterIn.PATH, name = "id", description = "Valueset ID"),
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Valueset JSON Object",
                content = @Content(schema = @Schema(implementation = String.class))
            ),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                )),
            @ApiResponse(
                responseCode = "404",
                description = "Valueset not found",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                ))
        }
    )
    public ResponseEntity<String> getValueset(@PathVariable("id") String id) {

        Optional<String> valueset = valuesetService.getValueSetById(id);

        if (valueset.isEmpty()) {
            throw new DgcgResponseException(
                HttpStatus.NOT_FOUND,
                "0x100",
                "Valueset not found",
                String.format("Requested valueset id %s", id),
                "Use the GET /valuesets endpoint to get a list of available valueset ids.");
        }

        return ResponseEntity
            .status(HttpStatus.OK)
            .contentType(MediaType.APPLICATION_JSON)
            .body(valueset.get());
    }

}
