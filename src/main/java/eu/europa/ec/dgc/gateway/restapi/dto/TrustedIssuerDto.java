package eu.europa.ec.dgc.gateway.restapi.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

import java.time.ZonedDateTime;

@Getter
@Setter
public class TrustedIssuerDto {

    @Schema(example = "https://url")
    private String url;

    @Schema(example = "HTTP")
    private UrlTypeDto type;

    @Schema(example = "EU")
    private String country;

    @Schema(example = "aaba14fa10c3a2fb441a28af0ec1bb4128153b9ddc796b66bfa04b02ea3e103e")
    private String thumbprint;

    @Schema(example = "o53CbAa77LyIMFc5Gz+B2Jc275Gdg/SdLayw7gx0GrTcinR95zfTLr8nNHgJMYlX3rD8Y11zB/Osyt0 ..."
            + " W+VIrYRGSEmgjGy2EwzvA5nVhsaA+/udnmbyQw9LjAOQ==")
    private String sslPublicKey;

    @Schema(example = "JWKS")
    private String keyStorageType;

    @Schema(example = "o53CbAa77LyIMFc5Gz+B2Jc275Gdg/SdLayw7gx0GrTcinR95zfTLr8nNHgJMYlX3rD8Y11zB/Osyt0 ..."
            + " W+VIrYRGSEmgjGy2EwzvA5nVhsaA+/udnmbyQw9LjAOQ==")
    private String signature;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ssXXX")
    private ZonedDateTime timestamp;

    public enum UrlTypeDto {
        HTTP,
        DID
    }
}
