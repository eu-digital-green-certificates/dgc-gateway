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

package eu.europa.ec.dgc.gateway.restapi.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedPartyRepository;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class CountryListIntegrationTest {

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    TrustedPartyRepository trustedPartyRepository;

    @Autowired
    DgcConfigProperties dgcConfigProperties;

    private static final String countryCode = "EU";
    private static final String authCertSubject = "C=EU";

    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void testData() {
        trustedPartyRepository.deleteAll();
    }

    @Test
    void testGetTrustedParties() throws Exception {
        // Insert some Certificates for random Countries
        trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, "AA");
        trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, "AB");
        trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, "AC");
        trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, "AD");

        String authCertHash =
          trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/countrylist")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
          )
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON))
          .andExpect(jsonPath("$.length()").value(5))
          .andExpect(jsonPath("$[0]").value("AA"))
            .andExpect(jsonPath("$[1]").value("AB"))
            .andExpect(jsonPath("$[2]").value("AC"))
            .andExpect(jsonPath("$[3]").value("AD"))
            .andExpect(jsonPath("$[4]").value(countryCode));
    }
}
