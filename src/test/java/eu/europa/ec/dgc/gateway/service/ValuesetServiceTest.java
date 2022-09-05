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

package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.entity.ValuesetEntity;
import eu.europa.ec.dgc.gateway.repository.ValuesetRepository;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class ValuesetServiceTest {

    @Autowired
    ValuesetService valuesetService;

    @Autowired
    ValuesetRepository valuesetRepository;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    CertificateUtils certificateUtils;

    @BeforeEach
    void setup() {
        valuesetRepository.deleteAll();
    }

    @Test
    void testGetValuesetIds() {
        ValuesetEntity valuesetEntity1 = new ValuesetEntity("vs-dummy-1", "content1");
        ValuesetEntity valuesetEntity2 = new ValuesetEntity("vs-dummy-2", "content2");
        ValuesetEntity valuesetEntity3 = new ValuesetEntity("vs-dummy-3", "content3");

        valuesetRepository.save(valuesetEntity1);
        valuesetRepository.save(valuesetEntity2);
        valuesetRepository.save(valuesetEntity3);


        List<String> valuesetIds = valuesetService.getValuesetIds();
        Assertions.assertEquals(3, valuesetService.getValuesetIds().size());
        Assertions.assertTrue(valuesetIds.contains("vs-dummy-1"));
        Assertions.assertTrue(valuesetIds.contains("vs-dummy-2"));
        Assertions.assertTrue(valuesetIds.contains("vs-dummy-3"));
    }

    @Test
    void testGetValueset() {
        ValuesetEntity valuesetEntity1 = new ValuesetEntity("vs-dummy-1", "content1");
        ValuesetEntity valuesetEntity2 = new ValuesetEntity("vs-dummy-2", "content2");

        valuesetRepository.save(valuesetEntity1);
        valuesetRepository.save(valuesetEntity2);

        Assertions.assertEquals(valuesetEntity1.getJson(),
          valuesetService.getValueSetById(valuesetEntity1.getId()).orElseThrow());
        Assertions.assertEquals(valuesetEntity2.getJson(),
          valuesetService.getValueSetById(valuesetEntity2.getId()).orElseThrow());
    }


}
