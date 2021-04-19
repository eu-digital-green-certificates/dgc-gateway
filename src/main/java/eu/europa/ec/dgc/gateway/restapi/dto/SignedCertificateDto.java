package eu.europa.ec.dgc.gateway.restapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.cert.X509CertificateHolder;

@Schema(
    name = "Signed Certificate (CMS)",
    type = "string",
    example = "MIICyDCCAbCgAwIBAgIGAXR3DZUUMA0GCSqGSIb3DQEBBQUAMBwxCzAJBgNVBAYT"
        + "AkRFMQ0wCwYDVQQDDARkZW1vMB4XDTIwMDgyNzA4MDY1MloXDTIxMDkxMDA4MDY1"
        + "MlowHDELMAkGA1UEBhMCREUxDTALBgNVBAMMBGRlbW8wggEiMA0GCSqGSIb3DQEB"
        + "AQUAA4IBDwAwggEKAoIBAQCKR0TEJOO4z0ks4OMAovcyxuPpeZuR1JykNNFd3OR+"
        + "vFWJLJtDYgRjtuqSuKCghLa/ci+0yIs3OeitGtajqFIukYksvX2LxOZDYDUbnpGQ"
        + "DPNMVmpEavDBbvKON8C8K036pC41bNvwkTrfUyZ8iE+hV2+kj1SHUyw7jweEUoiw"
        + "NmMiaXXPiMIOj7D0qnmM+iTGN9g/DrJ/IvvsgiGpK3QlQ5pnHs2BvzrSw4LFAZ8c"
        + "SQfWKheZVHfQf26mJFdEzowrzfzForDdeFAPIIirhufE3jWFxj1thfztu+VSMj84"
        + "sDqodEt2VJOY+DvLB1Ls/26LSmFtMnCEuBAhkbQ1E0tbAgMBAAGjEDAOMAwGA1Ud"
        + "EwEB/wQCMAAwDQYJKoZIhvcNAQEFBQADggEBABaMEQz4Gbj+G0SZGZaIDoUFDB6n"
        + "1R6iUS0zTBgsV8pSpFhwPryRiLdeNzIzsDdQ1ack1NfQ6YPn3/yOJ/SvnXs6n+vO"
        + "WQW2KsuiymPSd/wjeywRRMfCysHjrmE+m+8lrFDrKuPnrACwQIsX9PDEsRRBnpSy"
        + "5NKUZn6u3iPV9x6rwYCdCa/8VDGLqVb3eEE5dbFaYG9uW02cSbmsiZm8KmW8b6BF"
        + "eIwHVRAH6Cs1VZI8UIrdVGCE111tUo/0957rF+/doFyJcwX+4ESH0m2MsHFjXDfG"
        + "U8yTjiUh/b2Erk4TCmrJpux30QRhsNZwkmEYSbRv+vp5/obgH1mL5ouoV5I="
)
@Data
@Builder
@AllArgsConstructor
public class SignedCertificateDto {

    private final X509CertificateHolder payloadCertificate;
    private final X509CertificateHolder signerCertificate;
    private final String rawMessage;

    private final boolean verified;

}
