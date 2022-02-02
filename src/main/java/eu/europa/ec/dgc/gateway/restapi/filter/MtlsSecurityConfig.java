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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

@Configuration
@Profile("mtls")
@Slf4j
public class MtlsSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .x509()
            .userDetailsService(userDetailsService())
            .x509PrincipalExtractor(new ThumbprintX509PrincipalExtractor());
    }

    @Override
    protected UserDetailsService userDetailsService() {
        return hash -> new User(hash, "", Collections.emptyList());
    }

    private static class ThumbprintX509PrincipalExtractor implements X509PrincipalExtractor {

        @Override
        public Object extractPrincipal(X509Certificate x509Certificate) {

            try {
                String hash = DigestUtils.sha256Hex(x509Certificate.getEncoded());
                log.debug("Got certificate from request with hash {}", hash);
                return hash;
            } catch (CertificateEncodingException e) {
                log.error("Failed to extract bytes from certificate");
                return null;
            }
        }
    }
}

