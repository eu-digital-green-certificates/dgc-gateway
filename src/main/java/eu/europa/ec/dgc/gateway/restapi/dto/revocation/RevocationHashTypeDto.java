package eu.europa.ec.dgc.gateway.restapi.dto.revocation;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Type of hash for revocation lists")
public enum RevocationHashTypeDto {

    @Schema(description = "The hash is calculated over the UCI string encoded in "
        + "UTF-8 and converted to a byte array.")
    UCI,

    @Schema(description = "The hash is calculated over the bytes of the COSE_SIGN1 signature from the CWT")
    SIGNATURE,

    @Schema(description = "The CountryCode encoded as a UTF-8 string concatenated with the UCI encoded with a"
        + " UTF-8 string. This is then converted to a byte array and used as input to the hash function.")
    COUNTRYCODEUCI

}
