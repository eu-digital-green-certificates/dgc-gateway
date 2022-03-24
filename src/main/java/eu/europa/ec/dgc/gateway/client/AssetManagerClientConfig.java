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

package eu.europa.ec.dgc.gateway.client;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import feign.Client;
import feign.codec.Encoder;
import feign.form.spring.SpringFormEncoder;
import feign.httpclient.ApacheHttpClient;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.cloud.openfeign.support.SpringEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class AssetManagerClientConfig {

    private final ObjectFactory<HttpMessageConverters> messageConverters;

    private final DgcConfigProperties config;

    /**
     * Form Encoder for Multipart File Upload.
     */
    @Bean
    public Encoder feignFormEncoder() {
        return new SpringFormEncoder(new SpringEncoder(messageConverters));
    }

    /**
     * Configure the client depending on the ssl properties.
     *
     * @return an Apache Http Client with or without SSL features
     */
    @Bean
    public Client assetManagerClient() throws NoSuchAlgorithmException {
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();

        httpClientBuilder.setSSLContext(SSLContext.getDefault());
        httpClientBuilder.setSSLHostnameVerifier(new DefaultHostnameVerifier());

        /*if (config.getJrc().getProxy().getHost() != null
            && config.getJrc().getProxy().getPort() != -1
            && !config.getJrc().getProxy().getHost().isEmpty()) {
            log.info("Using Proxy for ASSETMANAGER Connection");
            // Set proxy
            httpClientBuilder.setProxy(new HttpHost(
                config.getJrc().getProxy().getHost(),
                config.getJrc().getProxy().getPort()
            ));

            // Set proxy authentication
            if (config.getJrc().getProxy().getUsername() != null
                && config.getJrc().getProxy().getPassword() != null
                && !config.getJrc().getProxy().getUsername().isEmpty()
                && !config.getJrc().getProxy().getPassword().isEmpty()) {

                log.info("Using Proxy with Authentication for ASSETMANAGER Connection");

                CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(
                    new AuthScope(
                        config.getJrc().getProxy().getHost(),
                        config.getJrc().getProxy().getPort()),
                    new UsernamePasswordCredentials(
                        config.getJrc().getProxy().getUsername(),
                        config.getJrc().getProxy().getPassword()));

                httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
            }
        } else {
            log.info("Using no proxy for ASSETMANAGER Connection");
        }*/

        return new ApacheHttpClient(httpClientBuilder.build());
    }
}
