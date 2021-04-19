package eu.europa.ec.dgc.gateway.restapi.controller;

import eu.europa.ec.dgc.gateway.restapi.converter.CmsMessageConverter;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedCertificateDto;
import eu.europa.ec.dgc.gateway.service.SignerInformationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/signerCertificate")
@Slf4j
@RequiredArgsConstructor
public class SignerCertificateController {

    private static final String X_DGC_HASH_HEADER = "X-DGC-HASH";

    private final SignerInformationService signerInformationService;

    /**
     * Http Method for publishing new signer certificate.
     */
    @PostMapping(path = "/", consumes = CmsMessageConverter.CONTENT_TYPE_CMS_VALUE)
    @Operation(
        summary = "Uploads Signer Certificate of a trusted Issuer",
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
                name = HttpHeaders.CONTENT_ENCODING,
                required = true,
                schema = @Schema(type = "string"),
                example = "base64")
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
        @RequestBody SignedCertificateDto cms
    ) {

        log.info("Signer Cert: {}", cms.getSignerCertificate().getSubject().toString());
        log.info("Payload Cert: {}", cms.getPayloadCertificate().getSubject().toString());

        try {
            signerInformationService.addSignerCertificate(
                cms.getPayloadCertificate(),
                cms.getSignerCertificate(),
                cms.getRawMessage(),
                "DE");
        } catch (SignerInformationService.SignerCertCheckException e) {

        }

        return ResponseEntity.status(201).build();
    }

    /**
     * Http Method for revoking signer certificate.
     */
    @DeleteMapping(path = "/")
    @Operation(
        summary = "Revokes Signer Certificate of a trusted Issuer",
        tags = {"Signer Information"},
        parameters = {
            @Parameter(
                in = ParameterIn.HEADER,
                name = X_DGC_HASH_HEADER,
                required = true,
                schema = @Schema(type = "string", format = "sha256"),
                example = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        },
        responses = {
            @ApiResponse(
                responseCode = "204",
                description = "Certificate was revoked successfully."),
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
        }
    )
    public ResponseEntity<Void> revokeVerificationInformation(
        @RequestHeader(X_DGC_HASH_HEADER) String hash
    ) {

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

}
