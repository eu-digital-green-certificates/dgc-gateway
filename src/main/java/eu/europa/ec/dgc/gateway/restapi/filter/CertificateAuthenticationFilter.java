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

package eu.europa.ec.dgc.gateway.restapi.filter;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.service.TrustedPartyService;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@Slf4j
@Component
@AllArgsConstructor
public class CertificateAuthenticationFilter extends OncePerRequestFilter {

    public static final String REQUEST_PROP_COUNTRY = "reqPropCountry";
    public static final String REQUEST_PROP_THUMBPRINT = "reqPropCertThumbprint";

    private final RequestMappingHandlerMapping requestMap;

    private final DgcConfigProperties properties;

    private final TrustedPartyService trustedPartyService;

    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        try {
            HandlerExecutionChain handlerExecutionChain = requestMap.getHandler(request);

            if (handlerExecutionChain == null) {
                return true;
            } else {
                return !((HandlerMethod) handlerExecutionChain.getHandler()).getMethod()
                    .isAnnotationPresent(CertificateAuthenticationRequired.class);
            }
        } catch (Exception e) {
            handlerExceptionResolver.resolveException(request, null, null, e);
            return true;
        }
    }

    private String normalizeCertificateHash(String inputString) {
        if (inputString == null) {
            return null;
        }

        boolean isHexString;
        // check if it is a hex string
        try {
            Hex.decode(inputString);
            isHexString = true;
        } catch (DecoderException ignored) {
            isHexString = false;
        }

        // We can assume that the given string is hex encoded SHA-256 hash when length is 64 and string is hex encoded
        if (inputString.length() == 64 && isHexString) {
            return inputString;
        } else {
            try {
                String hexString;
                if (inputString.contains("%")) { // only url decode input string if it contains none base64 characters
                    inputString = URLDecoder.decode(inputString, StandardCharsets.UTF_8);
                }
                hexString = Hex.toHexString(Base64.getDecoder().decode(inputString));
                return hexString;
            } catch (IllegalArgumentException ignored) {
                log.error("Could not normalize certificate hash.");
                return null;
            }
        }
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest httpServletRequest,
        HttpServletResponse httpServletResponse,
        FilterChain filterChain
    ) throws ServletException, IOException {
        logger.debug("Checking request for auth headers");

        String headerDistinguishedName =
            httpServletRequest.getHeader(properties.getCertAuth().getHeaderFields().getDistinguishedName());

        String headerCertThumbprint = normalizeCertificateHash(
            httpServletRequest.getHeader(properties.getCertAuth().getHeaderFields().getThumbprint()));

        if (headerDistinguishedName == null || headerCertThumbprint == null) {
            log.error("No thumbprint or distinguish name");
            handlerExceptionResolver.resolveException(
                httpServletRequest,
                httpServletResponse,
                null,
                new DgcgResponseException(
                    HttpStatus.UNAUTHORIZED,
                    "0x400",
                    "No thumbprint or distinguish name",
                    "", ""));
            return;
        }

        headerDistinguishedName = URLDecoder.decode(headerDistinguishedName, StandardCharsets.UTF_8);

        DgcMdc.put("dnString", headerDistinguishedName);
        DgcMdc.put("thumbprint", headerCertThumbprint);

        Map<String, String> distinguishNameMap = parseDistinguishNameString(headerDistinguishedName);

        if (!distinguishNameMap.containsKey("C")) {
            log.error("Country property is missing");
            handlerExceptionResolver.resolveException(
                httpServletRequest, httpServletResponse, null,
                new DgcgResponseException(
                    HttpStatus.BAD_REQUEST,
                    "0x401",
                    "Client Certificate must contain country property",
                    headerDistinguishedName, ""));
            return;
        }

        Optional<TrustedPartyEntity> certFromDb = trustedPartyService.getCertificate(
            headerCertThumbprint,
            distinguishNameMap.get("C"),
            TrustedPartyEntity.CertificateType.AUTHENTICATION
        );

        if (certFromDb.isEmpty()) {
            log.error("Unknown client certificate");
            handlerExceptionResolver.resolveException(
                httpServletRequest, httpServletResponse, null,
                new DgcgResponseException(
                    HttpStatus.UNAUTHORIZED,
                    "0x402",
                    "Client is not authorized to access the service",
                    "", ""));

            return;
        }

        log.info("Successful Authentication");
        httpServletRequest.setAttribute(REQUEST_PROP_COUNTRY, distinguishNameMap.get("C"));
        httpServletRequest.setAttribute(REQUEST_PROP_THUMBPRINT, headerCertThumbprint);

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    /**
     * Parses a given Distinguish Name string (e.g. "C=DE,OU=Test Unit,O=Test Company").
     *
     * @param dnString the DN string to parse.
     * @return Map with properties of the DN string.
     */
    private Map<String, String> parseDistinguishNameString(String dnString) {
        return Arrays.stream(dnString.split(","))
            .map(part -> part.split("="))
            .filter(entry -> entry.length == 2)
            .collect(Collectors.toMap(arr -> arr[0].toUpperCase().trim(), arr -> arr[1].trim(), (s, s2) -> s));
    }
}
