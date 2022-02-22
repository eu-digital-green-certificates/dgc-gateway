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

import eu.europa.ec.dgc.gateway.entity.TrustedReferenceEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;


public interface TrustedReferenceRepository extends JpaRepository<TrustedReferenceEntity, Long> {

    @Modifying
    @Query("DELETE FROM TrustedReferenceEntity r WHERE r.uuid = :uuid")
    int deleteByUuid(@Param("uuid") String uuid);

    Optional<TrustedReferenceEntity> getByUuid(String uuid);

    List<TrustedReferenceEntity> getAllByCountry(String country);

    @Query("SELECT t FROM TrustedReferenceEntity t WHERE "
        + "(:ignoreCountry = true OR t.country IN (:country)) AND "
        + "(:ignoreDomain = true OR t.domain IN (:domain)) AND "
        + "(:ignoreType = true OR t.type IN(:type)) AND "
        + "(:ignoreSignatureType = true OR t.signatureType IN(:signatureType)) AND "
        + "t.sourceGateway.gatewayId IS NULL")
    List<TrustedReferenceEntity> searchNonFederated(
        @Param("country") List<String> country,
        @Param("ignoreCountry") boolean ignoreCountry,
        @Param("domain") List<String> domain,
        @Param("ignoreDomain") boolean ignoreDomain,
        @Param("type") List<TrustedReferenceEntity.ReferenceType> type,
        @Param("ignoreType") boolean ignoreType,
        @Param("signatureType") List<TrustedReferenceEntity.SignatureType> signatureType,
        @Param("ignoreSignatureType") boolean ignoreSignatureType);

    @Query("SELECT t FROM TrustedReferenceEntity t WHERE "
        + "(:ignoreCountry = true OR t.country IN (:country)) AND "
        + "(:ignoreDomain = true OR t.domain IN (:domain)) AND "
        + "(:ignoreType = true OR t.type IN(:type)) AND "
        + "(:ignoreSignatureType = true OR t.signatureType IN(:signatureType))")
    List<TrustedReferenceEntity> search(
        @Param("country") List<String> country,
        @Param("ignoreCountry") boolean ignoreCountry,
        @Param("domain") List<String> domain,
        @Param("ignoreDomain") boolean ignoreDomain,
        @Param("type") List<TrustedReferenceEntity.ReferenceType> type,
        @Param("ignoreType") boolean ignoreType,
        @Param("signatureType") List<TrustedReferenceEntity.SignatureType> signatureType,
        @Param("ignoreSignatureType") boolean ignoreSignatureType);

}
