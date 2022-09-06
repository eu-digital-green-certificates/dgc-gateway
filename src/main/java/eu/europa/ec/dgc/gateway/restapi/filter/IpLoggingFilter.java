/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 - 2022 T-Systems International GmbH and all other contributors
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

import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@Component
@AllArgsConstructor
public class IpLoggingFilter extends OncePerRequestFilter {

    public static final String MDC_PROPERTY_SOURCE_IP = "sourceIP";

    public static final String HTTP_HEADER_FORWARDED_FOR = "X-Forwarded-For";

    @Override
    protected void doFilterInternal(
        HttpServletRequest httpServletRequest,
        HttpServletResponse httpServletResponse,
        FilterChain filterChain
    ) throws ServletException, IOException {
        logger.debug("Checking request for X-Forwarded-For headers");

        String headerForwardedFor =
            httpServletRequest.getHeader(HTTP_HEADER_FORWARDED_FOR);

        if (headerForwardedFor == null) {
            log.error("No source IP in request");
        } else {
            DgcMdc.put(MDC_PROPERTY_SOURCE_IP, headerForwardedFor);
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
