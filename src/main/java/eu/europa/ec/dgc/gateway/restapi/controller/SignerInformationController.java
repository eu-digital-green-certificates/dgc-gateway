package eu.europa.ec.dgc.gateway.restapi.controller;

import eu.europa.ec.dgc.gateway.restapi.converter.CmsMessageConverter;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedCertificateDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/signerInformation")
@Slf4j
public class SignerInformationController {

    private static final String X_DGC_HASH_HEADER = "X-DGC-HASH";

    /**
     * Http Method for publishing new signer information.
     */
    @PostMapping(path = "/", consumes = CmsMessageConverter.CONTENT_TYPE_CMS_VALUE)
    @Operation(
        summary = "Publishes Signer Information of a trusted Issuer",
        tags = {"Signer Information"},
        parameters = {
            @Parameter(
                in = ParameterIn.HEADER,
                name = HttpHeaders.CONTENT_TYPE,
                required = true,
                schema = @Schema(type = "string"),
                example = CmsMessageConverter.CONTENT_TYPE_CMS_VALUE),
            @Parameter(
                in = ParameterIn.HEADER,
                name = X_DGC_HASH_HEADER,
                required = true,
                schema = @Schema(type = "string", format = "SHA256"),
                example = "82f231898694e893389f7fc7f0d4b2ae1ddfb69e")
        },
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            description = "Request body with payload. (limited)",
            content = @Content(
                mediaType = CmsMessageConverter.CONTENT_TYPE_CMS_VALUE,
                schema = @Schema(implementation = SignedCertificateDto.class))
        ),
        responses = {
            @ApiResponse(
                responseCode = "201",
                description = "Verification Information was created successfully."),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)
                )),
            @ApiResponse(
                responseCode = "403",
                description = "Forbidden. Verification Information package is not accepted. (hash Value or signature"
                    + " wrong, client certificate matches not to the signer of the package)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "406",
                description = "Content is not acceptable. (Wrong Format, no CMS, not the correct signing alg,"
                    + " missing attributes etc.)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
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
        @RequestHeader(X_DGC_HASH_HEADER) String hash
    ) {

        log.info("Signer Cert: {}", cms.getSignerCertificate().getSubject().toString());
        log.info("Payload Cert: {}", cms.getPayloadCertificate().getSubject().toString());

        return ResponseEntity.status(201).build();
    }

}
