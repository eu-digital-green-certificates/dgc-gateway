package eu.europa.ec.dgc.gateway.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.ZonedDateTime;
import lombok.Data;

/**
 * This class only represents by DGCG required properties of the Validation Rule JSON.
 */
@Data
public class ParsedValidationRule {

    @JsonProperty("Identifier")
    String identifier;

    @JsonProperty("Type")
    String type;

    @JsonProperty("Country")
    String country;

    @JsonProperty("Version")
    String version;

    @JsonProperty("CertificateType")
    String certificateType;

    @JsonProperty("ValidFrom")
    ZonedDateTime validFrom;

    @JsonProperty("ValidTo")
    ZonedDateTime validTo;

}
