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

import eu.europa.ec.dgc.gateway.entity.RevocationBatchEntity;
import eu.europa.ec.dgc.gateway.entity.RevocationBatchProjection;
import jakarta.transaction.Transactional;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
@Transactional
public interface RevocationBatchRepository extends JpaRepository<RevocationBatchEntity, Long> {

    @Modifying
    @Query("DELETE FROM RevocationBatchEntity r WHERE r.batchId = :batchId")
    int deleteByBatchId(@Param("batchId") String batchId);

    Optional<RevocationBatchEntity> getByBatchId(String batchId);

    @Modifying
    @Query("""
        UPDATE RevocationBatchEntity r SET r.signedBatch = null, r.deleted = true,
        r.changed = :currentTimestamp WHERE r.batchId = :batchId""")
    int markBatchAsDeleted(@Param("batchId") String batchId,
                           @Param("currentTimestamp") ZonedDateTime currentTimestamp);

    @Modifying
    @Query("""
        UPDATE RevocationBatchEntity r SET r.signedBatch = null, r.deleted = true,
        r.changed = :currentTimestamp WHERE r.deleted = false AND r.expires < :threshold""")
    int markExpiredBatchesAsDeleted(@Param("threshold") ZonedDateTime threshold,
                                    @Param("currentTimestamp") ZonedDateTime currentTimestamp);

    @Modifying
    @Query("DELETE FROM RevocationBatchEntity r WHERE r.deleted = true AND r.changed < :threshold")
    int deleteDeletedBatchesOlderThan(@Param("threshold") ZonedDateTime threshold);

    List<RevocationBatchProjection> getAllByChangedGreaterThanOrderByChangedAsc(ZonedDateTime date, Pageable page);

    List<RevocationBatchEntity> getAllByCountry(String country);
}
