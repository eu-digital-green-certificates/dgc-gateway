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


import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedIssuerRepository;
import eu.europa.ec.dgc.gateway.testdata.TrustedIssuerTestHelper;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class TrustedIssuerServiceTest {

    @Autowired
    TrustedIssuerRepository trustedIssuerRepository;

    @Autowired
    TrustedIssuerTestHelper trustedIssuerTestHelper;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    TrustedIssuerService underTest;

    @BeforeEach
    void testData() throws Exception {
        trustedIssuerRepository.deleteAll();

        trustedIssuerRepository.saveAll(List.of(
            trustedIssuerTestHelper.createTrustedIssuer("EU"),
            trustedIssuerTestHelper.createTrustedIssuer("DE"),
            trustedIssuerTestHelper.createTrustedIssuer("AT")
        ));
    }

    @Test
    void testGetAll() {
        assertThat(underTest.getAllIssuers(), hasSize(3));
    }

    @Test
    void testEmptySignature() throws Exception {
        int originalSize = underTest.getAllIssuers().size();
        TrustedIssuerEntity data = trustedIssuerTestHelper.createTrustedIssuer("BE");
        data.setSignature("");
        trustedIssuerRepository.save(data);
        assertThat(underTest.getAllIssuers(), hasSize(originalSize));
    }

    @Test
    void testParsingSignatureError() throws Exception {
        int originalSize = underTest.getAllIssuers().size();
        TrustedIssuerEntity data = trustedIssuerTestHelper.createTrustedIssuer("BE");
        data.setSignature("WRONG");
        trustedIssuerRepository.save(data);
        assertThat(underTest.getAllIssuers(), hasSize(originalSize));
    }

    @Test
    void testWrongSignatureError() throws Exception {
        int originalSize = underTest.getAllIssuers().size();
        TrustedIssuerEntity data = trustedIssuerTestHelper.createTrustedIssuer("BE");
        data.setSignature(trustedPartyTestHelper.signString("WRONG"));
        trustedIssuerRepository.save(data);
        assertThat(underTest.getAllIssuers(), hasSize(originalSize));
    }
}
