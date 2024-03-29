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

package eu.europa.ec.dgc.gateway.testdata;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;

@Profile("!int-test")
@TestConfiguration
public class DgcTestKeyStore {

    private final DgcConfigProperties configProperties;

    @Getter
    private final X509Certificate trustAnchor;

    @Getter
    private final PrivateKey trustAnchorPrivateKey;

    @Getter
    private final X509Certificate publicationSigner;

    @Getter
    private final PrivateKey publicationSignerPrivateKey;

    public DgcTestKeyStore(DgcConfigProperties configProperties) throws Exception {
        this.configProperties = configProperties;

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        trustAnchorPrivateKey = keyPair.getPrivate();
        trustAnchor = CertificateTestUtils.generateCertificate(keyPair, "DE", "DGCG Test TrustAnchor");

        KeyPair keyPairPublication = KeyPairGenerator.getInstance("ec").generateKeyPair();
        publicationSignerPrivateKey = keyPairPublication.getPrivate();
        publicationSigner = CertificateTestUtils.generateCertificate(keyPairPublication, "DE", "DGCG Test Publication");

    }

    /**
     * Creates a KeyStore instance with keys for DGC.
     */
    @Bean
    @Primary
    @Qualifier("trustAnchor")
    public KeyStore testKeyStore() throws IOException, CertificateException, NoSuchAlgorithmException {
        KeyStoreSpi keyStoreSpiMock = mock(KeyStoreSpi.class);
        KeyStore keyStoreMock = new KeyStore(keyStoreSpiMock, null, "test") {
        };
        keyStoreMock.load(null);

        doAnswer((x) -> trustAnchor)
            .when(keyStoreSpiMock).engineGetCertificate(configProperties.getTrustAnchor().getCertificateAlias());

        return keyStoreMock;
    }

    /**
     * Creates a KeyStore instance with keys for DGC.
     */
    @Bean
    @Primary
    @Qualifier("publication")
    public KeyStore testPublicationKeyStore()
            throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStoreSpi keyStoreSpiMock = mock(KeyStoreSpi.class);
        KeyStore keyStoreMock = new KeyStore(keyStoreSpiMock, null, "test") {
        };
        keyStoreMock.load(null);

        doAnswer((x) -> publicationSigner)
                .when(keyStoreSpiMock)
                .engineGetCertificate(configProperties.getPublication().getKeystore().getCertificateAlias());

        doAnswer((x) -> publicationSignerPrivateKey)
                .when(keyStoreSpiMock)
                .engineGetKey(eq(configProperties.getPublication().getKeystore().getCertificateAlias()), any());

        return keyStoreMock;
    }

}
