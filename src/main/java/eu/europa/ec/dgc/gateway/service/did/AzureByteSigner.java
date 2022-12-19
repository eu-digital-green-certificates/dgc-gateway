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

package eu.europa.ec.dgc.gateway.service.did;

import com.azure.core.http.HttpClient;
import com.azure.core.http.ProxyOptions;
import com.azure.core.util.HttpClientOptions;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.danubetech.keyformats.crypto.ByteSigner;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(name = "dgc.did.didSigningProvider", havingValue = "azure")
public class AzureByteSigner extends ByteSigner {

    private final CryptographyClient cryptographyClient;

    /**
     * Setup {@link ByteSigner} implementation for MS Azure KeyVault to sign data with a secret.
     */
    public AzureByteSigner(DgcConfigProperties dgcConfigProperties) {
        super("EC");

        HttpClientOptions httpClientOptions = new HttpClientOptions();
        if (dgcConfigProperties.getDid().getAzure().getProxy().getHost() != null
            && dgcConfigProperties.getDid().getAzure().getProxy().getPort() != -1) {

            httpClientOptions.setProxyOptions(new ProxyOptions(
                ProxyOptions.Type.HTTP,
                new InetSocketAddress(dgcConfigProperties.getDid().getAzure().getProxy().getHost(),
                    + dgcConfigProperties.getDid().getAzure().getProxy().getPort())));
        }

        HttpClient httpClient = HttpClient.createDefault(httpClientOptions);

        cryptographyClient = new CryptographyClientBuilder()
            .keyIdentifier(dgcConfigProperties.getDid().getAzure().getSecretUrl())
            .credential(new ClientSecretCredentialBuilder()
                .httpClient(httpClient)
                .clientId(dgcConfigProperties.getDid().getAzure().getSpId())
                .clientSecret(dgcConfigProperties.getDid().getAzure().getSpSecret())
                .tenantId(dgcConfigProperties.getDid().getAzure().getSpTenant())
                .build())
            .httpClient(httpClient)
            .buildClient();
    }

    @Override
    protected byte[] sign(byte[] content) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content);
        SignResult signResult = cryptographyClient.sign(SignatureAlgorithm.ES256, hash);
        return signResult.getSignature();
    }
}
