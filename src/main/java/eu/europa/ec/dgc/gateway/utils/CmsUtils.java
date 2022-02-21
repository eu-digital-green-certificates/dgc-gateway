package eu.europa.ec.dgc.gateway.utils;

import eu.europa.ec.dgc.gateway.restapi.dto.SignedCertificateDto;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedStringDto;
import eu.europa.ec.dgc.signing.SignedCertificateMessageParser;
import eu.europa.ec.dgc.signing.SignedStringMessageParser;

public class CmsUtils {

    private CmsUtils() {
        //Utility class
    }

    /**
     * Get a signed payload String with signerCertificate and signature.
     */
    public static SignedStringDto getSignedString(final String cms) {
        SignedStringMessageParser messageParser = new SignedStringMessageParser(cms);
        return SignedStringDto.builder()
                .payloadString(messageParser.getPayload())
                .signerCertificate(messageParser.getSigningCertificate())
                .rawMessage(cms)
                .signature(messageParser.getSignature())
                .verified(messageParser.isSignatureVerified())
                .build();
    }

    /**
     * Get a signed payload certificate with signerCertificate and signature.
     */
    public static SignedCertificateDto getSignerCertificate(final String cms) {
        SignedCertificateMessageParser certificateParser = new SignedCertificateMessageParser(cms);
        return SignedCertificateDto.builder()
                .payloadCertificate(certificateParser.getPayload())
                .signerCertificate(certificateParser.getSigningCertificate())
                .rawMessage(cms)
                .signature(certificateParser.getSignature())
                .verified(certificateParser.isSignatureVerified())
                .build();
    }
}
