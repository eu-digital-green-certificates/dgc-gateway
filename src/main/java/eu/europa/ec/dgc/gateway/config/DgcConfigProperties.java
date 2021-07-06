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

package eu.europa.ec.dgc.gateway.config;

import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("dgc")
public class DgcConfigProperties {

    private final CertAuth certAuth = new CertAuth();
    private final TrustAnchor trustAnchor = new TrustAnchor();

    private String validationRuleSchema;

    private JrcConfig jrc = new JrcConfig();

    @Getter
    @Setter
    public static class JrcConfig {
        private String url;
        private Integer interval = 21_600_000;
        private ProxyConfig proxy = new ProxyConfig();
    }

    @Getter
    @Setter
    public static class ProxyConfig {

        private String host;
        private int port = -1;
        private String username;
        private String password;
    }

    @Getter
    @Setter
    public static class TrustAnchor {
        private String keyStorePath;
        private String keyStorePass;
        private String certificateAlias;
    }

    @Getter
    @Setter
    public static class CertAuth {

        private final HeaderFields headerFields = new HeaderFields();
        private List<String> certWhitelist;

        @Getter
        @Setter
        public static class HeaderFields {
            private String thumbprint;
            private String distinguishedName;
        }
    }
}
