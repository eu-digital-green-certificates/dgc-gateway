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
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class SignerInformationCleanUpService {

    private final SignerInformationRepository signerInformationRepository;

    private final DgcConfigProperties configProperties;

    /**
     * Delete SignerInformationEntity which are flagged for deletion.
     */
    @Scheduled(cron = "@daily")
    @SchedulerLock(name = "signer_information_cleanup")
    public void cleanup() {
        log.info("Starting SignerInformation Cleanup Job.");

        int affectedRowsDeleted = signerInformationRepository.deleteDeletedSignerInformationOlderThan(
            ZonedDateTime.now().minusDays(configProperties.getSignerInformation().getDeleteThreshold())
        );
        log.info("Deleted {} SignerInformation.", affectedRowsDeleted);

        log.info("Completed SignerInformation Cleanup Job.");
    }
}
