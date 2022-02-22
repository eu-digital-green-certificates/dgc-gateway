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

package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.model.TrustList;
import eu.europa.ec.dgc.gateway.model.TrustListType;
import eu.europa.ec.dgc.gateway.model.TrustedCertificateTrustList;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TrustListService {

    private final TrustedPartyService trustedPartyService;

    private final SignerInformationService signerInformationService;

    private final CertificateUtils certificateUtils;

    /**
     * Get a TrustList with TrustList Entries of all type and all country.
     *
     * @return List of {@link TrustList} ordered by KID
     */
    public List<TrustList> getTrustList() {
        return mergeAndConvert(
            trustedPartyService.getNonFederatedTrustedParties(),
            signerInformationService.getNonFederatedSignerInformation()
        );
    }

    /**
     * Get a TrustList with TrustList Entries of all countries filtered by type.
     *
     * @param type the type to filter for.
     * @return List of {@link TrustList} ordered by KID
     */
    public List<TrustList> getTrustList(TrustListType type) {
        if (type == TrustListType.DSC) {
            return mergeAndConvert(
                Collections.emptyList(),
                signerInformationService.getNonFederatedSignerInformation(SignerInformationEntity.CertificateType.DSC)
            );
        } else {
            return mergeAndConvert(
                trustedPartyService.getNonFederatedTrustedParties(map(type)),
                Collections.emptyList()
            );
        }
    }

    /**
     * Get a TrustList with TrustList Entries filtered by countriy and type.
     *
     * @param type        the type to filter for.
     * @param countryCode the 2-Digit country code to filter for.
     * @return List of {@link TrustList} ordered by KID
     */
    public List<TrustList> getTrustList(TrustListType type, String countryCode) {
        if (type == TrustListType.DSC) {
            return mergeAndConvert(
                Collections.emptyList(),
                signerInformationService.getNonFederatedSignerInformation(
                    countryCode, SignerInformationEntity.CertificateType.DSC)
            );
        } else {
            return mergeAndConvert(
                trustedPartyService.getCertificate(countryCode, map(type)),
                Collections.emptyList()
            );
        }
    }

    /**
     * Get a TrustList for TrustedCertificate Feature. List is filtered by given criteria.
     *
     * @param groups         List of groups to search for
     * @param country        List of country codes to search for
     * @param domain         List of domains to search for.
     * @param withFederation whether federated data should be included.
     * @return List of SignerInformation and TrustedParties.
     */
    public List<TrustedCertificateTrustList> getTrustedCertificateTrustList(
        List<String> groups, List<String> country, List<String> domain, boolean withFederation
    ) {
        return mergeAndConvertTrustedCertificate(
            trustedPartyService.getTrustedParties(groups, country, domain, withFederation),
            signerInformationService.getSignerInformation(groups, country, domain, withFederation)
        );
    }

    private List<TrustList> mergeAndConvert(
        List<TrustedPartyEntity> trustedPartyList,
        List<SignerInformationEntity> signerInformationList) {

        return Stream.concat(
                trustedPartyList.stream().map(this::convert),
                signerInformationList.stream().map(this::convert)
            )
            .sorted(Comparator.comparing(TrustList::getKid))
            .collect(Collectors.toList());
    }

    private List<TrustedCertificateTrustList> mergeAndConvertTrustedCertificate(
        List<TrustedPartyEntity> trustedPartyList,
        List<SignerInformationEntity> signerInformationList) {

        return Stream.concat(
                trustedPartyList.stream().map(this::convertTrustedCertificate),
                signerInformationList.stream().map(this::convertTrustedCertificate)
            )
            .sorted(Comparator.comparing(TrustedCertificateTrustList::getKid))
            .collect(Collectors.toList());
    }

    private TrustedCertificateTrustList convertTrustedCertificate(TrustedPartyEntity trustedPartyEntity) {
        return new TrustedCertificateTrustList(
            getKid(trustedPartyEntity),
            trustedPartyEntity.getCreatedAt(),
            trustedPartyEntity.getCountry(),
            trustedPartyEntity.getCertificateType().toString(),
            trustedPartyEntity.getThumbprint(),
            trustedPartyEntity.getRawData(),
            trustedPartyEntity.getSignature(),
            null,
            trustedPartyEntity.getSourceGateway() != null
                ? trustedPartyEntity.getSourceGateway().getGatewayId() : null,
            trustedPartyEntity.getUuid(),
            trustedPartyEntity.getDomain(),
            trustedPartyEntity.getVersion()
        );
    }

    private TrustedCertificateTrustList convertTrustedCertificate(SignerInformationEntity signerInformationEntity) {
        return new TrustedCertificateTrustList(
            getKid(signerInformationEntity),
            signerInformationEntity.getCreatedAt(),
            signerInformationEntity.getCountry(),
            signerInformationEntity.getCertificateType().toString(),
            signerInformationEntity.getThumbprint(),
            signerInformationEntity.getRawData(),
            signerInformationEntity.getSignature(),
            signerInformationEntity.getProperties(),
            signerInformationEntity.getSourceGateway() != null
                ? signerInformationEntity.getSourceGateway().getGatewayId() : null,
            signerInformationEntity.getUuid(),
            signerInformationEntity.getDomain(),
            signerInformationEntity.getVersion()
        );
    }

    private TrustList convert(TrustedPartyEntity trustedPartyEntity) {
        return new TrustList(
            getKid(trustedPartyEntity),
            trustedPartyEntity.getCreatedAt(),
            trustedPartyEntity.getCountry(),
            map(trustedPartyEntity.getCertificateType()),
            trustedPartyEntity.getThumbprint(),
            trustedPartyEntity.getSignature(),
            trustedPartyEntity.getRawData()
        );
    }

    private TrustList convert(SignerInformationEntity signerInformationEntity) {
        return new TrustList(
            getKid(signerInformationEntity),
            signerInformationEntity.getCreatedAt(),
            signerInformationEntity.getCountry(),
            map(signerInformationEntity.getCertificateType()),
            signerInformationEntity.getThumbprint(),
            signerInformationEntity.getSignature(),
            signerInformationEntity.getRawData()
        );
    }

    private String getKid(SignerInformationEntity signerInformationEntity) {
        return signerInformationEntity.getKid() == null
            ? certificateUtils.getCertKid(
            signerInformationService.getX509CertificateFromEntity(signerInformationEntity))
            : signerInformationEntity.getKid();
    }

    private String getKid(TrustedPartyEntity trustedPartyEntity) {
        return trustedPartyEntity.getKid() == null
            ? certificateUtils.getCertKid(
            trustedPartyService.getX509CertificateFromEntity(trustedPartyEntity))
            : trustedPartyEntity.getKid();
    }

    private TrustedPartyEntity.CertificateType map(TrustListType type) {
        return TrustedPartyEntity.CertificateType.valueOf(type.name());
    }

    private TrustListType map(Enum<?> type) {
        return TrustListType.valueOf(type.name());
    }

}
