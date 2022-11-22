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

import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;


public interface TrustedIssuerRepository extends JpaRepository<TrustedIssuerEntity, Long> {

    List<TrustedIssuerEntity> getAllByCountry(String country);

    List<TrustedIssuerEntity> getAllByCountryIn(List<String> country);

    @Query("SELECT t FROM TrustedIssuerEntity t WHERE "
        + "(:ignoreCountry = true OR t.country IN (:country)) AND "
        + "(:ignoreDomain = true OR t.domain IN (:domain)) AND "
        + "t.sourceGateway.gatewayId IS NULL")
    List<TrustedIssuerEntity> searchNonFederated(
        @Param("country") List<String> country,
        @Param("ignoreCountry") boolean ignoreCountry,
        @Param("domain") List<String> domain,
        @Param("ignoreDomain") boolean ignoreDomain);

    @Query("SELECT t FROM TrustedIssuerEntity t WHERE "
        + "(:ignoreCountry = true OR t.country IN (:country)) AND "
        + "(:ignoreDomain = true OR t.domain IN (:domain))")
    List<TrustedIssuerEntity> search(
        @Param("country") List<String> country,
        @Param("ignoreCountry") boolean ignoreCountry,
        @Param("domain") List<String> domain,
        @Param("ignoreDomain") boolean ignoreDomain);
}
