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

import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import java.util.List;
import java.util.Optional;
import javax.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface TrustedPartyRepository extends JpaRepository<TrustedPartyEntity, Long> {

    List<TrustedPartyEntity> getBySourceGatewayIsNull();

    List<TrustedPartyEntity> getByCountryAndCertificateType(String country, TrustedPartyEntity.CertificateType type);

    List<TrustedPartyEntity> getByCertificateTypeAndSourceGatewayIsNull(TrustedPartyEntity.CertificateType type);

    Optional<TrustedPartyEntity> getFirstByThumbprintAndCountryAndCertificateType(
        String thumbprint, String country, TrustedPartyEntity.CertificateType type);

    Optional<TrustedPartyEntity> getFirstByThumbprintAndCertificateType(
        String thumbprint, TrustedPartyEntity.CertificateType type);

    @Query("SELECT DISTINCT t.country FROM TrustedPartyEntity t WHERE t.sourceGateway IS NULL")
    List<String> getCountryCodeList();

    @Transactional
    Long deleteBySourceGatewayGatewayId(String gatewayId);

    @Query("SELECT t FROM TrustedPartyEntity t WHERE "
        + "(:ignoreGroup = true OR t.certificateType IN (:group)) AND "
        + "(:ignoreCountry = true OR t.country IN (:country)) AND "
        + "(:ignoreDomain = true OR t.domain IN (:domain)) AND "
        + "t.sourceGateway.gatewayId IS NULL")
    List<TrustedPartyEntity> searchNonFederated(
        @Param("group") List<TrustedPartyEntity.CertificateType> group,
        @Param("ignoreGroup") boolean ignoreGroup,
        @Param("country") List<String> country,
        @Param("ignoreCountry") boolean ignoreCountry,
        @Param("domain") List<String> domain,
        @Param("ignoreDomain") boolean ignoreDomain);

    @Query("SELECT t FROM TrustedPartyEntity t WHERE "
        + "(:ignoreGroup = true OR t.certificateType IN (:group)) AND "
        + "(:ignoreCountry = true OR t.country IN (:country)) AND "
        + "(:ignoreDomain = true OR t.domain IN (:domain))")
    List<TrustedPartyEntity> search(
        @Param("group") List<TrustedPartyEntity.CertificateType> group,
        @Param("ignoreGroup") boolean ignoreGroup,
        @Param("country") List<String> country,
        @Param("ignoreCountry") boolean ignoreCountry,
        @Param("domain") List<String> domain,
        @Param("ignoreDomain") boolean ignoreDomain);

}
