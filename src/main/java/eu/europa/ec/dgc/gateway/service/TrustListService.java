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

package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.model.TrustList;
import eu.europa.ec.dgc.gateway.model.TrustListType;
import eu.europa.ec.dgc.gateway.utils.ListUtils;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.time.ZonedDateTime;
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
            trustedPartyService.getCertificates(),
            signerInformationService.getSignerInformation()
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
                signerInformationService.getSignerInformation(SignerInformationEntity.CertificateType.DSC)
            );
        } else {
            return mergeAndConvert(
                trustedPartyService.getCertificates(map(type)),
                Collections.emptyList()
            );
        }
    }

    /**
     * Get a TrustList with TrustList Entries filtered by country and type.
     *
     * @param type        the type to filter for.
     * @param countryCode the 2-Digit country code to filter for.
     * @return List of {@link TrustList} ordered by KID
     */
    public List<TrustList> getTrustList(TrustListType type, String countryCode) {
        if (type == TrustListType.DSC) {
            return mergeAndConvert(
                Collections.emptyList(),
                signerInformationService.getSignerInformation(countryCode, SignerInformationEntity.CertificateType.DSC)
            );
        } else {
            return mergeAndConvert(
                trustedPartyService.getCertificates(countryCode, map(type)),
                Collections.emptyList()
            );
        }
    }

    /**
     * Finds a list of TrustList.
     * Optional the list can be filtered by a timestamp and paginated.
     *
     * @param ifModifiedSince since timestamp for filtering TrustList.
     * @param page zero-based page index, must NOT be negative.
     * @param size number of items in a page to be returned, must be greater than 0.
     * @return List of {@link TrustList} ordered by KID
     */
    public List<TrustList> getTrustList(ZonedDateTime ifModifiedSince,
                                        Integer page, Integer size) {

        List<TrustList> fullTrustLists;

        if (ifModifiedSince == null) {
            fullTrustLists = mergeAndConvert(
                trustedPartyService.getCertificates(),
                signerInformationService.getSignerInformation());
        } else {
            fullTrustLists = mergeAndConvert(
                trustedPartyService.getCertificates(ifModifiedSince, null, null),
                signerInformationService.getSignerInformation(ifModifiedSince, null, null)
            );
        }
        if (page != null && size != null) {
            return ListUtils.getPage(fullTrustLists, page, size);
        } else {
            return fullTrustLists;
        }
    }

    /**
     * Finds a list of TrustList filtered by type.
     * Optional the list can be filtered by a timestamp and paginated.
     *
     * @param type the type to filter for.
     * @param ifModifiedSince since timestamp for filtering TrustList.
     * @param page zero-based page index, must NOT be negative.
     * @param size number of items in a page to be returned, must be greater than 0.
     * @return List of {@link TrustList} ordered by KID
     */
    public List<TrustList> getTrustList(TrustListType type,
                                        ZonedDateTime ifModifiedSince,
                                        Integer page, Integer size) {
        List<TrustList> trustListsByType;

        if (ifModifiedSince == null) {
            if (type == TrustListType.DSC) {
                trustListsByType = mergeAndConvert(Collections.emptyList(),
                    signerInformationService.getSignerInformation(SignerInformationEntity.CertificateType.DSC));
            } else {
                trustListsByType = mergeAndConvert(trustedPartyService.getCertificates(map(type)),
                    Collections.emptyList());
            }
        } else {
            if (type == TrustListType.DSC) {
                trustListsByType = mergeAndConvert(Collections.emptyList(),
                        signerInformationService.getSignerInformation(SignerInformationEntity.CertificateType.DSC,
                            ifModifiedSince, null, null));
            } else {
                trustListsByType = mergeAndConvert(trustedPartyService.getCertificates(map(type),
                    ifModifiedSince, null, null),
                    Collections.emptyList());
            }
        }
        if (page != null && size != null) {
            return ListUtils.getPage(trustListsByType, page, size);
        } else {
            return trustListsByType;
        }
    }

    /**
     *  Finds a list of TrustList filtered by country and type.
     *  Optional the list can be filtered by a timestamp and paginated.
     *
     * @param type        the type to filter for.
     * @param countryCode the 2-Digit country code to filter for.
     * @param ifModifiedSince since timestamp for filtering TrustList.
     * @param page zero-based page index, must NOT be negative.
     * @param size number of items in a page to be returned, must be greater than 0.
     * @return List of {@link TrustList} ordered by KID
     */
    public List<TrustList> getTrustList(TrustListType type, String countryCode,
                                        ZonedDateTime ifModifiedSince,
                                        Integer page, Integer size) {
        List<TrustList> trustListsByTypeAndCountry;

        if (ifModifiedSince == null) {
            if (type == TrustListType.DSC) {
                trustListsByTypeAndCountry = mergeAndConvert(Collections.emptyList(),
                    signerInformationService.getSignerInformation(countryCode,
                        SignerInformationEntity.CertificateType.DSC));
            } else {
                trustListsByTypeAndCountry = mergeAndConvert(
                    trustedPartyService.getCertificates(countryCode, map(type)),
                    Collections.emptyList());
            }
        } else {
            if (type == TrustListType.DSC) {
                trustListsByTypeAndCountry = mergeAndConvert(Collections.emptyList(),
                    signerInformationService.getSignerInformation(countryCode,
                        SignerInformationEntity.CertificateType.DSC,
                        ifModifiedSince, null, null));
            } else {
                trustListsByTypeAndCountry = mergeAndConvert(
                    trustedPartyService.getCertificates(countryCode, map(type),
                        ifModifiedSince, null, null),
                    Collections.emptyList());
            }
        }
        if (page != null && size != null) {
            return ListUtils.getPage(trustListsByTypeAndCountry, page, size);
        } else {
            return trustListsByTypeAndCountry;
        }
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

    private TrustList convert(TrustedPartyEntity trustedPartyEntity) {
        return new TrustList(
            certificateUtils.getCertKid(trustedPartyService.getX509CertificateFromEntity(trustedPartyEntity)),
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
            certificateUtils.getCertKid(signerInformationService.getX509CertificateFromEntity(signerInformationEntity)),
            signerInformationEntity.getCreatedAt(),
            signerInformationEntity.getCountry(),
            map(signerInformationEntity.getCertificateType()),
            signerInformationEntity.getThumbprint(),
            signerInformationEntity.getSignature(),
            signerInformationEntity.getDeletedAt() == null ? signerInformationEntity.getRawData() : null
        );
    }

    private TrustedPartyEntity.CertificateType map(TrustListType type) {
        return TrustedPartyEntity.CertificateType.valueOf(type.name());
    }

    private TrustListType map(Enum<?> type) {
        return TrustListType.valueOf(type.name());
    }

}
