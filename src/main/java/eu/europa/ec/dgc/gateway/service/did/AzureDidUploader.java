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
import com.azure.core.util.BinaryData;
import com.azure.core.util.HttpClientOptions;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.BlobHttpHeaders;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import java.net.InetSocketAddress;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

@ConditionalOnProperty(name = "dgc.did.didUploadProvider", havingValue = "azure")
@Service
@Slf4j
public class AzureDidUploader implements DidUploader {

    private final BlobClient blobClient;

    private final DgcConfigProperties dgcConfigProperties;

    /**
     * Setup instance of {@link DidUploader} to upload generated DID Documents to Azure BLOB Storage.
     */
    public AzureDidUploader(DgcConfigProperties dgcConfigProperties) {
        this.dgcConfigProperties = dgcConfigProperties;

        HttpClientOptions httpClientOptions = new HttpClientOptions();
        if (dgcConfigProperties.getDid().getAzure().getProxy().getHost() != null
            && dgcConfigProperties.getDid().getAzure().getProxy().getPort() != -1) {

            httpClientOptions.setProxyOptions(new ProxyOptions(
                ProxyOptions.Type.HTTP,
                new InetSocketAddress(dgcConfigProperties.getDid().getAzure().getProxy().getHost(),
                    + dgcConfigProperties.getDid().getAzure().getProxy().getPort())));
        }

        HttpClient httpClient = HttpClient.createDefault(httpClientOptions);

        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .httpClient(httpClient)
            .endpoint(dgcConfigProperties.getDid().getAzure().getBlobEndpoint())
            .credential(new ClientSecretCredentialBuilder()
                .httpClient(httpClient)
                .clientId(dgcConfigProperties.getDid().getAzure().getSpId())
                .clientSecret(dgcConfigProperties.getDid().getAzure().getSpSecret())
                .tenantId(dgcConfigProperties.getDid().getAzure().getSpTenant())
                .build())
            .buildClient();

        BlobContainerClient blobContainerClient = blobServiceClient.getBlobContainerClient(
            dgcConfigProperties.getDid().getAzure().getBlobContainer());

        blobClient = blobContainerClient.getBlobClient(dgcConfigProperties.getDid().getAzure().getBlobName());
    }

    @Override
    public void uploadDid(byte[] content) {
        log.info("Uploading {} bytes as {}{}/{} to Azure BLOB Storage", content.length,
            dgcConfigProperties.getDid().getAzure().getBlobEndpoint(),
            dgcConfigProperties.getDid().getAzure().getBlobContainer(),
            dgcConfigProperties.getDid().getAzure().getBlobName());

        blobClient.upload(BinaryData.fromBytes(content), true);
        blobClient.setHttpHeaders(new BlobHttpHeaders().setContentType(MediaType.APPLICATION_JSON_VALUE));
        log.info("Upload successful");
    }

}
