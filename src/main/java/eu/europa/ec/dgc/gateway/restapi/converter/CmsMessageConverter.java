/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
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

package eu.europa.ec.dgc.gateway.restapi.converter;

import eu.europa.ec.dgc.gateway.restapi.dto.SignedCertificateDto;
import eu.europa.ec.dgc.signing.SignedCertificateMessageParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
@Slf4j
public class CmsMessageConverter extends AbstractHttpMessageConverter<SignedCertificateDto> {

    public static final MediaType CONTENT_TYPE_CMS = new MediaType("application", "cms");
    public static final String CONTENT_TYPE_CMS_VALUE = "application/cms";

    public CmsMessageConverter() {
        super(CONTENT_TYPE_CMS);
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return SignedCertificateDto.class.isAssignableFrom(clazz);
    }

    @Override
    protected SignedCertificateDto readInternal(
        Class<? extends SignedCertificateDto> clazz,
        HttpInputMessage inputMessage
    ) throws IOException, HttpMessageNotReadableException {

        byte[] inputBytes = inputMessage.getBody().readAllBytes();
        SignedCertificateMessageParser certificateParser = new SignedCertificateMessageParser(inputBytes);

        switch (certificateParser.getParserState()) {
            case FAILURE_INVALID_BASE64:
                throw badRequest("Invalid Base64 CMS Message");
            case FAILURE_INVALID_CMS:
                throw badRequest("Could not parse CMS Message");
            case FAILURE_INVALID_CMS_BODY:
                throw badRequest("CMS Message needs to have binary data as body.");
            case FAILURE_CMS_SIGNING_CERT_INVALID:
                throw badRequest("CMS Message needs to contain exactly one X509 certificate");
            case FAILURE_CMS_SIGNER_INFO:
                throw badRequest("CMS Message needs to have exactly 1 signer information.");
            case FAILURE_CMS_BODY_NO_CERTIFICATE:
                throw badRequest("CMS Message payload needs to be a DER encoded X509 certificate");
            default:
        }

        return SignedCertificateDto.builder()
            .payloadCertificate(certificateParser.getPayloadCertificate())
            .signerCertificate(certificateParser.getSigningCertificate())
            .rawMessage(new String(inputBytes, StandardCharsets.UTF_8))
            .signature(certificateParser.getSignature())
            .verified(certificateParser.isSignatureVerified())
            .build();
    }

    @Override
    protected void writeInternal(SignedCertificateDto signedCertificateDto, HttpOutputMessage outputMessage)
        throws HttpMessageNotWritableException {
        throw new HttpMessageNotWritableException("Outbound Usage of CMS Messages is currently not supported!");
    }

    private ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
