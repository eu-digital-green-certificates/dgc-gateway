package eu.europa.ec.dgc.gateway.model;

import java.time.ZonedDateTime;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TrustList {

    private String kid;

    private ZonedDateTime timestamp;

    private String country;

    private TrustListType certificateType;

    private String thumbprint;

    private String signature;

    private String rawData;
}
