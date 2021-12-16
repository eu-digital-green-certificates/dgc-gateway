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

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.repository.RevocationBatchRepository;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class RevocationListCleanUpService {

    private final RevocationBatchRepository revocationBatchRepository;

    private final DgcConfigProperties configProperties;

    /**
     * Delete Revocation Batches which expiry date is reached.
     */
    @Scheduled(cron = "0 0 4 * * *")
    @SchedulerLock(name = "revocation_batch_cleanup")
    public void cleanup() {
        log.info("Starting Revocation List Cleanup Job.");

        int affectedRowsMarkAsDeleted = revocationBatchRepository.markExpiredBatchesAsDeleted(ZonedDateTime.now());
        log.info("Marked {} Revocation Batches as deleted.", affectedRowsMarkAsDeleted);

        int affectedRowsDeleted = revocationBatchRepository.deleteDeletedBatchesOlderThan(
            ZonedDateTime.now().minusDays(configProperties.getRevocation().getDeleteThreshold()));
        log.info("Deleted {} Revocation Batches.", affectedRowsDeleted);

        log.info("Completed Revocation List Cleanup Job.");
    }
}
