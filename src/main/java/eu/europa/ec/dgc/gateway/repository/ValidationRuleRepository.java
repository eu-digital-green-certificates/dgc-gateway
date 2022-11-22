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

import eu.europa.ec.dgc.gateway.entity.ValidationRuleEntity;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import javax.transaction.Transactional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
@Transactional
public interface ValidationRuleRepository extends JpaRepository<ValidationRuleEntity, Long> {

    Optional<ValidationRuleEntity> getFirstByRuleIdOrderByIdDesc(String ruleId);

    @Query("SELECT v.id FROM ValidationRuleEntity v WHERE "
        + "v.validFrom <= :threshold AND v.ruleId = :ruleId ORDER BY v.id DESC")
    List<Long> getIdByValidFromIsBeforeAndRuleIdIs(
        @Param("threshold") ZonedDateTime threshold, @Param("ruleId") String ruleId, Pageable pageable);

    List<ValidationRuleEntity> getByRuleIdAndValidFromIsGreaterThanEqualOrderByIdDesc(
        String ruleId, ZonedDateTime threshold);

    @Query("SELECT max(v.id) FROM ValidationRuleEntity v WHERE v.country = :country GROUP BY v.ruleId")
    List<Long> getLatestIds(@Param("country") String countryCode);

    List<ValidationRuleEntity> getByIdIsGreaterThanEqualAndRuleIdIsOrderByIdDesc(Long minimumId, String ruleId);

    @Modifying
    @Query("DELETE FROM ValidationRuleEntity v WHERE v.ruleId = :ruleId")
    int deleteByRuleId(@Param("ruleId") String ruleId);

    Optional<ValidationRuleEntity> getByRuleIdAndVersion(String ruleId, String version);

    List<ValidationRuleEntity> getAllByCountry(String country);

}
