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

package eu.europa.ec.dgc.gateway.repository;

import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import javax.transaction.Transactional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SignerInformationRepository extends JpaRepository<SignerInformationEntity, Long> {

    String SELECT_SINCE =
        "SELECT s FROM SignerInformationEntity s WHERE s.createdAt >= :since OR s.deletedAt >= :since";
    String SELECT_BY_TYPE_SINCE =
        "SELECT s FROM SignerInformationEntity s WHERE s.certificateType = :certType AND (s.createdAt >= :since "
            + " OR s.deletedAt >= :since)";
    String SELECT_BY_TYPE_AND_COUNTRY_SINCE =
        "SELECT s FROM SignerInformationEntity s"
            + " WHERE s.certificateType = :certType AND s.country = :country AND (s.createdAt >= :since"
            + " OR s.deletedAt >= :since)";

    List<SignerInformationEntity> getAllBySourceGatewayIsNull();

    @Query("SELECT s FROM SignerInformationEntity s WHERE "
        + "(:ignoreGroup = true OR s.certificateType IN (:group)) AND "
        + "(:ignoreCountry = true OR s.country IN (:country)) AND "
        + "(:ignoreDomain = true OR s.domain IN (:domain))")
    List<SignerInformationEntity> search(
        @Param("group") List<SignerInformationEntity.CertificateType> group,
        @Param("ignoreGroup") boolean ignoreGroup,
        @Param("country") List<String> country,
        @Param("ignoreCountry") boolean ignoreCountry,
        @Param("domain") List<String> domain,
        @Param("ignoreDomain") boolean ignoreDomain);

    @Query("SELECT s FROM SignerInformationEntity s WHERE "
        + "(:ignoreGroup = true OR s.certificateType IN (:group)) AND "
        + "(:ignoreCountry = true OR s.country IN (:country)) AND "
        + "(:ignoreDomain = true OR s.domain IN (:domain)) AND "
        + "s.sourceGateway.gatewayId IS NULL")
    List<SignerInformationEntity> searchNonFederated(
        @Param("group") List<SignerInformationEntity.CertificateType> group,
        @Param("ignoreGroup") boolean ignoreGroup,
        @Param("country") List<String> country,
        @Param("ignoreCountry") boolean ignoreCountry,
        @Param("domain") List<String> domain,
        @Param("ignoreDomain") boolean ignoreDomain);

    Optional<SignerInformationEntity> getFirstByThumbprint(String thumbprint);

    Optional<SignerInformationEntity> getFirstByThumbprintStartsWithAndThumbprintIsNot(
        String thumbprintStart, String thumbprint);

    @Transactional
    @Modifying
    @Query("DELETE FROM SignerInformationEntity s WHERE s.deletedAt < :threshold")
    int deleteDeletedSignerInformationOlderThan(@Param("threshold") ZonedDateTime threshold);

    List<SignerInformationEntity> getByCertificateTypeAndDeletedAtIsNull(SignerInformationEntity.CertificateType type,
                                                                         Pageable pageable);

    List<SignerInformationEntity> getByCertificateTypeAndDeletedAtIsNull(SignerInformationEntity.CertificateType type);

    Optional<SignerInformationEntity> getFirstByKid(String kid);

    @Transactional
    void deleteByThumbprint(String thumbprint);

    List<SignerInformationEntity> getByCertificateTypeAndSourceGatewayIsNull(
        SignerInformationEntity.CertificateType type);

    List<SignerInformationEntity> getByCertificateTypeAndCountryAndSourceGatewayIsNull(
        SignerInformationEntity.CertificateType type, String countryCode);

    List<SignerInformationEntity> getBySourceGatewayGatewayId(String gatewayId);

    @Transactional
    Long deleteBySourceGatewayGatewayId(String gatewayId);

    List<SignerInformationEntity> getByCertificateTypeAndCountryAndDeletedAtIsNull(
        SignerInformationEntity.CertificateType type, String countryCode,
        Pageable pageable);

    List<SignerInformationEntity> getByCertificateTypeAndCountryAndDeletedAtIsNull(
        SignerInformationEntity.CertificateType type, String countryCode);

    @Query(SELECT_SINCE)
    List<SignerInformationEntity> getIsSince(@Param("since") ZonedDateTime since);

    @Query(SELECT_SINCE)
    List<SignerInformationEntity> getIsSince(@Param("since") ZonedDateTime since, Pageable pageable);

    List<SignerInformationEntity> getByDeletedAtIsNull();

    List<SignerInformationEntity> getByDeletedAtIsNull(Pageable pageable);

    @Query(SELECT_BY_TYPE_SINCE)
    List<SignerInformationEntity> getByCertificateTypeIsSince(
        @Param("certType") SignerInformationEntity.CertificateType type,
        @Param("since") ZonedDateTime since);

    @Query(SELECT_BY_TYPE_SINCE)
    List<SignerInformationEntity> getByCertificateTypeIsSince(
        @Param("certType") SignerInformationEntity.CertificateType type,
        @Param("since") ZonedDateTime since, Pageable pageable);

    @Query(SELECT_BY_TYPE_AND_COUNTRY_SINCE)
    List<SignerInformationEntity> getByCertificateTypeAndCountryIsSince(
        @Param("certType") SignerInformationEntity.CertificateType type,
        @Param("country") String countryCode,
        @Param("since") ZonedDateTime since);

    @Query(SELECT_BY_TYPE_AND_COUNTRY_SINCE)
    List<SignerInformationEntity> getByCertificateTypeAndCountryIsSince(
        @Param("certType") SignerInformationEntity.CertificateType type,
        @Param("country") String countryCode,
        @Param("since") ZonedDateTime since, Pageable pageable);

}
