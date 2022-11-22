/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway
 * ---
 * Copyright (C) 2022 T-Systems International GmbH and all other contributors
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
