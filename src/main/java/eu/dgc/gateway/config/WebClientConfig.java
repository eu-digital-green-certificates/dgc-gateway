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

package eu.dgc.gateway.config;

import eu.dgc.gateway.mtls.DgcCallbackTrustManager;
import eu.dgc.gateway.mtls.ForceCertUsageX509KeyManager;
import io.netty.channel.ChannelOption;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.timeout.ReadTimeoutHandler;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLException;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.ProxyProvider;

@Configuration
@RequiredArgsConstructor
public class WebClientConfig {

  private final DgcConfigProperties dgcConfigProperties;

  private final KeyStore callbackKeyStore;

  private final DgcCallbackTrustManager dgcCallbackTrustManager;

  /**
   * Configures WebClient for HTTP requests for callback feature.
   *
   * @return Instance of WebClient
   * @throws UnrecoverableKeyException if the key cannot be recovered
   * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
   * @throws KeyStoreException if the keystore has not been initialized
   * @throws SSLException if the SSL context cannot be build
   */
  @Bean
  public WebClient webClient() throws UnrecoverableKeyException, NoSuchAlgorithmException,
          KeyStoreException, SSLException {

    PrivateKey privateKey = (PrivateKey) callbackKeyStore.getKey(
      dgcConfigProperties.getCallback().getKeyStorePrivateKeyAlias(),
      dgcConfigProperties.getCallback().getKeyStorePass().toCharArray()
    );

    X509Certificate certificate = (X509Certificate) callbackKeyStore.getCertificate(
      dgcConfigProperties.getCallback().getKeyStoreCertificateAlias()
    );

    SslContext sslContext = SslContextBuilder
      .forClient()
      .enableOcsp(false)
      .keyManager(new ForceCertUsageX509KeyManager(privateKey, certificate))
      .trustManager(dgcCallbackTrustManager)
      .build();

    HttpClient httpClient = HttpClient.create()
      .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext))
        .responseTimeout(Duration.of(dgcConfigProperties.getCallback().getTimeout(), ChronoUnit.MILLIS))
        .proxy(proxyOptions -> {
            if (dgcConfigProperties.getCallback().getProxyHost() != null
                && !dgcConfigProperties.getCallback().getProxyHost().isEmpty()) {
                proxyOptions
                        .type(ProxyProvider.Proxy.HTTP)
                        .host(dgcConfigProperties.getCallback().getProxyHost())
                        .port(dgcConfigProperties.getCallback().getProxyPort())
                        .username(dgcConfigProperties.getCallback().getProxyUser())
                        .password(s -> dgcConfigProperties.getCallback().getProxyPassword());
            }
        });

    return WebClient.builder()
      .clientConnector(new ReactorClientHttpConnector(httpClient))
      .build();
  }
}
