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
import java.util.List;
import java.util.Optional;
import javax.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SignerInformationRepository extends JpaRepository<SignerInformationEntity, Long> {

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

    Optional<SignerInformationEntity> getFirstByKid(String kid);

    @Transactional
    void deleteByThumbprint(String thumbprint);

    List<SignerInformationEntity> getByCertificateTypeAndSourceGatewayIsNull(
        SignerInformationEntity.CertificateType type);

    List<SignerInformationEntity> getByCertificateTypeAndCountryAndSourceGatewayIsNull(
        SignerInformationEntity.CertificateType type, String countryCode);

    @Transactional
    Long deleteBySourceGatewayGatewayId(String gatewayId);

}
