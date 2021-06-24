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

import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.dto.SignedStringDto;
import eu.europa.ec.dgc.signing.SignedStringMessageParser;
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

@Component
@Slf4j
public class CmsStringMessageConverter extends AbstractHttpMessageConverter<SignedStringDto> {

    public static final MediaType CONTENT_TYPE_CMS_TEXT = new MediaType("application", "cms-text");
    public static final String CONTENT_TYPE_CMS_TEXT_VALUE = "application/cms-text";

    public CmsStringMessageConverter() {
        super(CONTENT_TYPE_CMS_TEXT);
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return SignedStringDto.class.isAssignableFrom(clazz);
    }

    @Override
    protected SignedStringDto readInternal(
        Class<? extends SignedStringDto> clazz,
        HttpInputMessage inputMessage
    ) throws IOException, HttpMessageNotReadableException {

        byte[] inputBytes = inputMessage.getBody().readAllBytes();
        SignedStringMessageParser parser = new SignedStringMessageParser(inputBytes);

        switch (parser.getParserState()) {
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
            case FAILURE_CMS_BODY_PARSING_FAILED:
                throw badRequest("CMS Message payload needs to be a String");
            default:
        }

        return SignedStringDto.builder()
            .payloadString(parser.getPayload())
            .signerCertificate(parser.getSigningCertificate())
            .rawMessage(new String(inputBytes, StandardCharsets.UTF_8))
            .signature(parser.getSignature())
            .verified(parser.isSignatureVerified())
            .build();
    }

    @Override
    protected void writeInternal(SignedStringDto signedStringDto, HttpOutputMessage outputMessage)
        throws HttpMessageNotWritableException {
        throw new HttpMessageNotWritableException("Outbound Usage of CMS Messages is currently not supported!");
    }

    private DgcgResponseException badRequest(String message) {
        return new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x402", message, "", "");
    }
}
