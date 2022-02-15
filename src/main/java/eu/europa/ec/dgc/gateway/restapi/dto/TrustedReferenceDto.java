package eu.europa.ec.dgc.gateway.restapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import javax.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;


@Schema(description = "Trusted refernece representation.")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TrustedReferenceDto {

    private String uuid;

    private String version;

    @Schema(description = "ISO 3166 2-Digit Country Code")
    @Length(min = 2, max = 2)
    @NotNull
    private String country;

    private ReferenceTypeDto type;

    private String service;

    private String thumbprint;

    private String name;

    private String sslPublicKey;

    private String contentType;

    private SignatureTypeDto signatureType;

    public enum ReferenceTypeDto {
        DCC,
        FHIR
    }

    public enum SignatureTypeDto {
        CMS,
        JWS,
        NONE
    }

}
