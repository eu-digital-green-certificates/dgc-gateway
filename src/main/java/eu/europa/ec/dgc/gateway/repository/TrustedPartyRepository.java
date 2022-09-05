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

package eu.europa.ec.dgc.gateway.repository;

import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface TrustedPartyRepository extends JpaRepository<TrustedPartyEntity, Long> {

    String SELECT_SINCE = "SELECT t FROM TrustedPartyEntity t WHERE t.createdAt >= :since";
    String SELECT_BY_TYPE_SINCE =
        "SELECT t FROM TrustedPartyEntity t WHERE t.certificateType = :certType AND t.createdAt >= :since";
    String SELECT_BY_TYPE_AND_COUNTRY_SINCE =
        "SELECT t FROM TrustedPartyEntity t"
            + " WHERE t.certificateType = :certType AND t.country = :country AND t.createdAt >= :since";

    List<TrustedPartyEntity> getByCountryAndCertificateType(String country, TrustedPartyEntity.CertificateType type);

    List<TrustedPartyEntity> getByCertificateType(TrustedPartyEntity.CertificateType type);

    Optional<TrustedPartyEntity> getFirstByThumbprintAndCountryAndCertificateType(
        String thumbprint, String country, TrustedPartyEntity.CertificateType type);

    Optional<TrustedPartyEntity> getFirstByThumbprintAndCertificateType(
        String thumbprint, TrustedPartyEntity.CertificateType type);

    @Query("SELECT DISTINCT t.country FROM TrustedPartyEntity t")
    List<String> getCountryCodeList();

    @Query(SELECT_SINCE)
    List<TrustedPartyEntity> getIsSince(@Param("since") ZonedDateTime since);

    @Query(SELECT_BY_TYPE_SINCE)
    List<TrustedPartyEntity> getByCertificateTypeIsSince(
      @Param("certType") TrustedPartyEntity.CertificateType type,
      @Param("since") ZonedDateTime since);

    @Query(SELECT_BY_TYPE_AND_COUNTRY_SINCE)
    List<TrustedPartyEntity> getByCountryAndCertificateTypeIsSince(
      @Param("country") String countryCode,
      @Param("certType") TrustedPartyEntity.CertificateType type,
      @Param("since") ZonedDateTime since);

}
