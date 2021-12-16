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

import eu.europa.ec.dgc.gateway.entity.RevocationBatchEntity;
import eu.europa.ec.dgc.gateway.repository.RevocationBatchRepository;
import eu.europa.ec.dgc.gateway.restapi.controller.CertificateRevocationListIntegrationTest;
import java.time.ZonedDateTime;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = "dgc.revocation.delete-threshold=14")
@Slf4j
class CertificateRevocationListCleanupTest {

    @Autowired
    RevocationBatchRepository revocationBatchRepository;

    @Autowired
    RevocationListCleanUpService cleanUpService;

    @BeforeEach
    public void setup() {
        revocationBatchRepository.deleteAll();
    }

    @Test
    public void testCleanup() {

        // Batch which expired 5 days ago --> marked as deleted
        RevocationBatchEntity e1 = new RevocationBatchEntity(
            null, "batchId1", "EU", ZonedDateTime.now(), ZonedDateTime.now().minusDays(5),
            false, RevocationBatchEntity.RevocationHashType.SIGNATURE, "UNKNOWN_KID", "cms");
        e1 = revocationBatchRepository.save(e1);

        // Batch which will expire within 2 days --> don't touch
        RevocationBatchEntity e2 = new RevocationBatchEntity(
            null, "batchId2", "EU", ZonedDateTime.now(), ZonedDateTime.now().plusDays(2),
            false, RevocationBatchEntity.RevocationHashType.SIGNATURE, "UNKNOWN_KID", "cms");
        e2 = revocationBatchRepository.save(e2);

        // Batch which is expired 5 days ago, marked as deleted 5 days ago --> don't touch
        RevocationBatchEntity e3 = new RevocationBatchEntity(
            null, "batchId3", "EU", ZonedDateTime.now().minusDays(5), ZonedDateTime.now().minusDays(5),
            true, RevocationBatchEntity.RevocationHashType.SIGNATURE, "UNKNOWN_KID", null);
        e3 = revocationBatchRepository.save(e3);

        // Batch which is expired 16 days ago, marked as deleted 16 days ago --> delete
        RevocationBatchEntity e4 = new RevocationBatchEntity(
            null, "batchId4", "EU", ZonedDateTime.now().minusDays(16), ZonedDateTime.now().minusDays(16),
            true, RevocationBatchEntity.RevocationHashType.SIGNATURE, "UNKNOWN_KID", null);
        e4 = revocationBatchRepository.save(e4);


        cleanUpService.cleanup();


        RevocationBatchEntity newE1 = revocationBatchRepository.getByBatchId(e1.getBatchId()).orElseThrow();
        Assertions.assertTrue(newE1.getDeleted());
        Assertions.assertNull(newE1.getSignedBatch());
        Assertions.assertTrue(newE1.getChanged().toEpochSecond() < ZonedDateTime.now().plusSeconds(2).toEpochSecond());
        Assertions.assertTrue(newE1.getChanged().toEpochSecond() > ZonedDateTime.now().minusSeconds(2).toEpochSecond());

        RevocationBatchEntity newE2 = revocationBatchRepository.getByBatchId(e2.getBatchId()).orElseThrow();
        CertificateRevocationListIntegrationTest.assertEquals(e2, newE2);

        RevocationBatchEntity newE3 = revocationBatchRepository.getByBatchId(e3.getBatchId()).orElseThrow();
        CertificateRevocationListIntegrationTest.assertEquals(e3, newE3);

        Assertions.assertTrue(revocationBatchRepository.getByBatchId(e4.getBatchId()).isEmpty());
    }


}
