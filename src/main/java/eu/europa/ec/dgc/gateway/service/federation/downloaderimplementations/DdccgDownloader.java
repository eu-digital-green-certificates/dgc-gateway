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
import eu.europa.ec.dgc.gateway.connector.mapper.TrustedCertificateMapper;
import eu.europa.ec.dgc.gateway.connector.mapper.TrustedIssuerMapper;
import eu.europa.ec.dgc.gateway.connector.mapper.TrustedReferenceMapper;
import eu.europa.ec.dgc.gateway.connector.model.TrustedCertificateTrustListItem;
import eu.europa.ec.dgc.gateway.connector.model.TrustedIssuer;
import eu.europa.ec.dgc.gateway.connector.model.TrustedReference;
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedReferenceEntity;
import eu.europa.ec.dgc.gateway.service.SignerInformationService;
import eu.europa.ec.dgc.gateway.service.TrustedIssuerService;
import eu.europa.ec.dgc.gateway.service.TrustedPartyService;
import eu.europa.ec.dgc.gateway.service.TrustedReferenceService;
import eu.europa.ec.dgc.gateway.service.federation.FederationDownloader;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.persistence.PersistenceException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;

@Service
@Qualifier(DdccgDownloader.downloaderIdentifier)
@Slf4j
@RequiredArgsConstructor
public class DdccgDownloader implements FederationDownloader {

    static final String downloaderIdentifier = "DdccDownloader_V1";

    private final SignerInformationService signerInformationService;
    private final TrustedPartyService trustedPartyService;
    private final TrustedIssuerService trustedIssuerService;
    private final TrustedReferenceService trustedReferenceService;

    private final ApplicationContext applicationContext;

    private final DgcConfigProperties configProperties;
    private final CertificateUtils certificateUtils;

    private final TrustListMapper trustListMapper;
    private final TrustedCertificateMapper trustedCertificateMapper;
    private final TrustedIssuerMapper trustedIssuerMapper;
    private final TrustedReferenceMapper trustedReferenceMapper;

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

        final List<TrustedCertificateTrustListItem> trustedCertificates = connector.getDdccTrustedCertificates();
        final List<TrustedReference> trustedReferences = connector.getTrustedReferences();
        final List<TrustedIssuer> trustedIssuers = connector.getTrustedIssuers();

        if (connector.getStatus() != null) {
            log.error("Failed to Download for Gateway {}: {}",
                gateway.getGatewayId(), connector.getStatus());

            throw new FederationDownloaderException("Failed to Download: " + connector.getStatus());
        }

        log.debug("Deleting existing data for Gateway {}", gateway.getGatewayId());
        signerInformationService.deleteSignerCertificateByFederationGateway(gateway.getGatewayId());
        trustedPartyService.deleteTrustedPartyByByFederationGateway(gateway.getGatewayId());
        trustedIssuerService.deleteBySourceGateway(gateway.getGatewayId());
        trustedReferenceService.deleteBySourceGateway(gateway.getGatewayId());

        log.debug("Persisting new data for Gateway {}: TrustedCertificate: {}",
            gateway.getGatewayId(), trustedCertificates.size());
        persistTrustedCertificates(gateway, trustedCertificates);
        persistTrustedReferences(gateway, trustedReferences);
        persistTrustedIssuer(gateway, trustedIssuers);
    }

    private DgcGatewayDownloadConnector instantiateConnector(FederationGatewayEntity gateway)
        throws DgcGatewayDownloadConnectorBuilder.DgcGatewayDownloadConnectorBuilderException,
        FederationDownloaderException {

        log.debug("Instantiating Download Connector for Gateway {}", gateway.getGatewayId());
        DgcGatewayDownloadConnectorBuilder builder;

        X509CertificateHolder clientCertificate;
        PrivateKey clientCertificateKey;

        try {
            clientCertificate = certificateUtils.convertCertificate(
                (X509Certificate) federationKeyStore.getCertificate(gateway.getGatewayKid()));
            clientCertificateKey = (PrivateKey) federationKeyStore.getKey(gateway.getGatewayKid(),
                configProperties.getFederation().getKeystoreKeyPassword().toCharArray());
        } catch (Exception e) {
            log.error("Failed to get Gateway Client Certificate from KeyStore: {}", e.getMessage());
            log.debug("Failed to get Gateway Client Certificate from KeyStore.", e);
            throw new FederationDownloaderException(
                "Failed to get Gateway Client Certificate from KeyStore: " + e.getMessage());
        }

        builder = new DgcGatewayDownloadConnectorBuilder(applicationContext, trustListMapper, trustedIssuerMapper,
            trustedReferenceMapper, trustedCertificateMapper)
            .withUrl(gateway.getGatewayEndpoint())
            .withMtlsAuthCert(clientCertificate, clientCertificateKey)
            .withDdccSupport(true)
            .withMaximumCacheAge(30);

        builder.withTrustAnchors(getTrustedPartyCerts(gateway, TrustedPartyEntity.CertificateType.TRUSTANCHOR));

        for (
            X509CertificateHolder cert :
            getTrustedPartyCerts(gateway, TrustedPartyEntity.CertificateType.AUTHENTICATION_FEDERATION)) {
            builder.withTrustedServerCert(cert);
        }

        log.debug("Successfully instantiated Download Connector for Gateway {}", gateway.getGatewayId());
        return builder.build();
    }

    private TrustedPartyEntity.CertificateType getTrustedPartyCertificateType(String group) {
        return Arrays.stream(TrustedPartyEntity.CertificateType.values())
            .filter(type -> group.equalsIgnoreCase(type.toString()))
            .findFirst()
            .orElse(null);
    }

    private SignerInformationEntity.CertificateType getSignerInformationCertificateType(String group) {
        return Arrays.stream(SignerInformationEntity.CertificateType.values())
            .filter(type -> group.equalsIgnoreCase(type.toString()))
            .findFirst()
            .orElse(null);
    }

    private void persistTrustedReferences(
        FederationGatewayEntity gateway, List<TrustedReference> trustedReferences) {

        trustedReferences.forEach(trustedReference -> {

            TrustedReferenceEntity.ReferenceType referenceType = TrustedReferenceEntity.ReferenceType.valueOf(
                trustedReference.getType().name());
            TrustedReferenceEntity.SignatureType signatureType = TrustedReferenceEntity.SignatureType.valueOf(
                trustedReference.getSignatureType().name());

            try {
                trustedReferenceService.addFederatedTrustedReference(trustedReference.getCountry(), referenceType,
                    trustedReference.getService(), trustedReference.getName(), signatureType,
                    trustedReference.getThumbprint(), trustedReference.getSslPublicKey(),
                    trustedReference.getReferenceVersion(), trustedReference.getContentType(), null,
                    trustedReference.getUuid(), gateway);

                log.debug("Successfully persisted federated TrustedReference. Gateway: {}, UUID: {}, Name: {}",
                    gateway.getGatewayId(), trustedReference.getUuid(), trustedReference.getName());
            } catch (PersistenceException e) {
                log.error("Failed to persist federated TrustedReference. Gateway: {}, UUID: {}, Name: {}",
                    gateway.getGatewayId(), trustedReference.getUuid(), trustedReference.getName());
            }
        });
    }

    private void persistTrustedIssuer(
        FederationGatewayEntity gateway, List<TrustedIssuer> trustedIssuers) {

        trustedIssuers.forEach(trustedIssuer -> {

            TrustedIssuerEntity.UrlType urlType = TrustedIssuerEntity.UrlType.valueOf(
                trustedIssuer.getType().name());

            try {
                trustedIssuerService.addFederatedTrustedIssuer(trustedIssuer.getCountry(), trustedIssuer.getUrl(),
                    trustedIssuer.getName(), urlType, trustedIssuer.getThumbprint(), trustedIssuer.getSslPublicKey(),
                    trustedIssuer.getKeyStorageType(), trustedIssuer.getSignature(), trustedIssuer.getDomain(),
                    trustedIssuer.getUuid(), null, gateway);

                log.debug("Successfully persisted federated TrustedIssuer. Gateway: {}, UUID: {}, Name: {}",
                    gateway.getGatewayId(), trustedIssuer.getUuid(), trustedIssuer.getName());
            } catch (PersistenceException e) {
                log.error("Failed to persist federated TrustedIssuer. Gateway: {}, UUID: {}, Name: {}",
                    gateway.getGatewayId(), trustedIssuer.getUuid(), trustedIssuer.getName());
            }
        });
    }

    private void persistTrustedCertificates(
        FederationGatewayEntity gateway, List<TrustedCertificateTrustListItem> trustedCertificateList) {

        final Map<TrustedPartyEntity.CertificateType, List<TrustedCertificateTrustListItem>> trustedParties =
            new HashMap<>();
        final Map<SignerInformationEntity.CertificateType, List<TrustedCertificateTrustListItem>> signerCerts =
            new HashMap<>();

        trustedCertificateList.forEach(trustedCertificate -> {

            TrustedPartyEntity.CertificateType trustedPartyType =
                getTrustedPartyCertificateType(trustedCertificate.getGroup());
            if (trustedPartyType != null) {
                // TrustedParty
                trustedParties.getOrDefault(trustedPartyType, new ArrayList<>())
                    .add(trustedCertificate);
                return;
            }

            SignerInformationEntity.CertificateType signerInformationType =
                getSignerInformationCertificateType(trustedCertificate.getGroup());
            if (signerInformationType != null) {
                // SignerInformation

                signerCerts.getOrDefault(signerInformationType, new ArrayList<>())
                    .add(trustedCertificate);
                return;
            }

            // Unknown TrustedCertificate Type
            log.error("Could not identify TrustedCertificate of Group {} as known CertificateType. KID: {}",
                trustedCertificate.getGroup(), trustedCertificate.getKid());
        });

        trustedParties.forEach((key, value) ->
            log.info("Persisting {} TrustedCertificates of group {}", key, value.size()));

        signerCerts.forEach((key, value) ->
            log.info("Persisting {} TrustedCertificates of group {}", key, value.size()));


        trustedParties.forEach((type, certList) -> {
            certList.forEach(trustedParty -> {
                try {
                    trustedPartyService.addFederatedTrustedParty(
                        trustedParty.getCertificate(),
                        trustedParty.getSignature(),
                        trustedParty.getCountry(),
                        trustedParty.getKid(),
                        trustedParty.getDomain(),
                        trustedParty.getUuid(),
                        type,
                        gateway
                    );
                } catch (IOException e) {
                    log.error("Failed to persist federated TrustedParty. Gateway: {}, Kid: {}",
                        gateway.getGatewayId(), trustedParty.getKid());
                }

                log.debug("Successfully persisted federated TrustedParty. Gateway: {}, Kid: {}",
                    gateway.getGatewayId(), trustedParty.getKid());
            });
        });

        signerCerts.forEach((type, certList) -> {
            certList.forEach(signerCert -> {
                try {
                    signerInformationService.addFederatedSignerCertificate(
                        signerCert.getCertificate(),
                        signerCert.getSignature(),
                        signerCert.getCountry(),
                        signerCert.getKid(),
                        signerCert.getDomain(),
                        signerCert.getUuid(),
                        Math.toIntExact(signerCert.getVersion()),
                        gateway
                    );
                } catch (SignerInformationService.SignerCertCheckException e) {
                    log.error("Failed to persist federated TrustedParty. Gateway: {}, Kid: {}",
                        gateway.getGatewayId(), signerCert.getKid());
                }

                log.debug("Successfully persisted federated TrustedParty. Gateway: {}, Kid: {}",
                    gateway.getGatewayId(), signerCert.getKid());
            });
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
