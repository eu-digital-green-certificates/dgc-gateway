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

package eu.europa.ec.dgc.gateway.service.federation.downloaderimplementations;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.connector.DgcGatewayDownloadConnector;
import eu.europa.ec.dgc.gateway.connector.DgcGatewayDownloadConnectorBuilder;
import eu.europa.ec.dgc.gateway.connector.mapper.TrustListMapper;
import eu.europa.ec.dgc.gateway.connector.model.TrustListItem;
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.service.SignerInformationService;
import eu.europa.ec.dgc.gateway.service.TrustedPartyService;
import eu.europa.ec.dgc.gateway.service.federation.FederationDownloader;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;

@Service
@Qualifier(LegacyDgcgDownloader.downloaderIdentifier)
@Slf4j
@RequiredArgsConstructor
public class LegacyDgcgDownloader implements FederationDownloader {

    static final String downloaderIdentifier = "legacyDgcgDownloader_V1";
    private final SignerInformationService signerInformationService;
    private final TrustedPartyService trustedPartyService;
    private final ApplicationContext applicationContext;
    private final TrustListMapper trustListMapper;
    private final DgcConfigProperties configProperties;
    private final CertificateUtils certificateUtils;
    @Qualifier("federation")
    private final KeyStore federationKeyStore;

    @Override
    public String getDownloaderIdentifier() {
        return downloaderIdentifier;
    }

    @Override
    public void incrementalDownload(FederationGatewayEntity gateway) throws FederationDownloaderException {
        throw new FederationDownloaderException("Incremental Download is not yet supported.");
    }

    @Override
    public void fullDownload(FederationGatewayEntity gateway) throws FederationDownloaderException {
        log.info("Downloading Data from Gateway {}", gateway.getGatewayId());

        DgcGatewayDownloadConnector connector;

        try {
            connector = instantiateConnector(gateway);
        } catch (DgcGatewayDownloadConnectorBuilder.DgcGatewayDownloadConnectorBuilderException e) {
            log.error("Failed to instantiate Download Connector for Gateway {}, {}, {}",
                gateway.getGatewayId(), e.getReason(), e.getMessage());

            throw new FederationDownloaderException("Failed to instantiate Download Connector: " + e.getReason());
        }

        final List<TrustListItem> trustList = connector.getTrustedCertificates();
        final List<TrustListItem> csca = connector.getTrustedCscaCertificates();
        final List<TrustListItem> upload = connector.getTrustedUploadCertificates();

        log.debug("Deleting existing data for Gateway {}", gateway.getGatewayId());
        signerInformationService.deleteSignerCertificateByFederationGateway(gateway.getGatewayId());
        trustedPartyService.deleteTrustedPartyByByFederationGateway(gateway.getGatewayId());

        log.debug("Persisting new data for Gateway {}: CSCA: {}, Upload: {}, SignerCertificate: {}",
            gateway.getGatewayId(), csca.size(), upload.size(), trustList.size());
        persistTrustedParty(gateway, connector.getTrustedCscaCertificates(), TrustedPartyEntity.CertificateType.CSCA);
        persistTrustedParty(
            gateway, connector.getTrustedUploadCertificates(), TrustedPartyEntity.CertificateType.UPLOAD);
        persistTrustList(gateway, trustList);
    }

    private DgcGatewayDownloadConnector instantiateConnector(FederationGatewayEntity gateway)
        throws DgcGatewayDownloadConnectorBuilder.DgcGatewayDownloadConnectorBuilderException,
        FederationDownloaderException {

        log.debug("Instantiating Download Connector for Gateway {}", gateway.getGatewayId());
        DgcGatewayDownloadConnectorBuilder builder;

        X509CertificateHolder clientCertificate;
        PrivateKey clientCertifikateKey;

        try {
            clientCertificate = certificateUtils.convertCertificate(
                (X509Certificate) federationKeyStore.getCertificate(gateway.getGatewayKid()));
            clientCertifikateKey = (PrivateKey) federationKeyStore.getKey(gateway.getGatewayKid(),
                configProperties.getFederation().getKeystoreKeyPassword().toCharArray());
        } catch (Exception e) {
            log.error("Failed to get Gateway Client Certificate from KeyStore: {}", e.getMessage());
            throw new FederationDownloaderException(
                "Failed to get Gateway Client Certificate from KeyStore: " + e.getMessage());
        }

        builder = new DgcGatewayDownloadConnectorBuilder(applicationContext, trustListMapper)
            .withUrl(gateway.getGatewayEndpoint())
            .withMtlsAuthCert(clientCertificate, clientCertifikateKey)
            .withMaximumCacheAge(0);

        builder.withTrustAnchors(getTrustedPartyCerts(gateway, TrustedPartyEntity.CertificateType.TRUSTANCHOR));

        for (
            X509CertificateHolder cert :
            getTrustedPartyCerts(gateway, TrustedPartyEntity.CertificateType.AUTHENTICATION_FEDERATION)) {
            builder.withTrustedServerCert(cert);
        }

        log.debug("Successfully instantiated Download Connector for Gateway {}", gateway.getGatewayId());
        return builder.build();
    }

    private void persistTrustedParty(
        FederationGatewayEntity gateway,
        List<TrustListItem> trustedPartyList,
        TrustedPartyEntity.CertificateType type) {

        trustedPartyList.forEach(trustListItem -> {
            try {
                trustedPartyService.addFederatedTrustedParty(
                    trustListItem.getRawData(),
                    trustListItem.getSignature(),
                    trustListItem.getCountry(),
                    null,
                    type,
                    gateway
                );
            } catch (IOException e) {
                log.error("Failed to persist federated TrustedParty. Gateway: {}, Thumbprint: {}",
                    gateway.getGatewayId(), trustListItem.getThumbprint());
            }

            log.debug("Successfully persisted federated TrustedParty. Gateway: {}, Thumbprint: {}",
                gateway.getGatewayId(), trustListItem.getThumbprint());
        });


    }

    private void persistTrustList(FederationGatewayEntity gateway, List<TrustListItem> downloadedTrustList) {

        downloadedTrustList.forEach(trustListItem -> {
            try {
                signerInformationService.addFederatedSignerCertificate(
                    trustListItem.getRawData(),
                    trustListItem.getSignature(),
                    trustListItem.getCountry(),
                    null,
                    gateway
                );
            } catch (SignerInformationService.SignerCertCheckException e) {
                log.error("Failed to persist federated SignerCertificate. Gateway: {}, Thumbprint: {}",
                    gateway.getGatewayId(), trustListItem.getThumbprint());
            }

            log.debug("Successfully persisted federated SignerCertificate. Gateway: {}, Thumbprint: {}",
                gateway.getGatewayId(), trustListItem.getThumbprint());
        });

    }

    private List<X509CertificateHolder> getTrustedPartyCerts(
        FederationGatewayEntity gateway, TrustedPartyEntity.CertificateType type) {
        return gateway.getTrustedParties().stream()
            .filter(trustedParty -> trustedParty.getCertificateType() == type)
            .map(trustedPartyService::getX509CertificateHolderFromEntity)
            .collect(Collectors.toList());
    }
}
