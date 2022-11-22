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

import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.entity.ValuesetEntity;
import eu.europa.ec.dgc.gateway.repository.ValuesetRepository;
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
class ValuesetIntegrationTest {

    @Autowired
    ValuesetRepository valuesetRepository;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    DgcConfigProperties dgcConfigProperties;

    @Autowired
    private MockMvc mockMvc;

    private static final String countryCode = "EU";
    private static final String authCertSubject = "C=" + countryCode;

    private static final ValuesetEntity valuesetEntity1 =
        new ValuesetEntity("vs-dummy-1", "{ \"key1\": \"content1\" }");
    private static final ValuesetEntity valuesetEntity2 =
        new ValuesetEntity("vs-dummy-2", "{ \"key2\": \"content2\" }");
    private static final ValuesetEntity valuesetEntity3 =
        new ValuesetEntity("vs-dummy-3", "{ \"key3\": \"content3\" }");

    @BeforeEach
    void testData() {
        valuesetRepository.deleteAll();

        valuesetRepository.save(valuesetEntity1);
        valuesetRepository.save(valuesetEntity2);
        valuesetRepository.save(valuesetEntity3);
    }

    @Test
    void testGetValuesetIds() throws Exception {
        String authCertHash =
          trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/valuesets")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
          )
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON))
          .andExpect(jsonPath("$.length()").value(equalTo(3)))
          .andExpect(jsonPath("$[0]").value(equalTo(valuesetEntity1.getId())))
            .andExpect(jsonPath("$[1]").value(equalTo(valuesetEntity2.getId())))
            .andExpect(jsonPath("$[2]").value(equalTo(valuesetEntity3.getId())));
    }

    @Test
    void testGetValueset() throws Exception {
        String authCertHash =
          trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/valuesets/" + valuesetEntity1.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
          )
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON))
          .andExpect(jsonPath("$.key1").value(equalTo("content1")));

        mockMvc.perform(get("/valuesets/" + valuesetEntity2.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
          )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.key2").value(equalTo("content2")));

        mockMvc.perform(get("/valuesets/" + valuesetEntity3.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
          )
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.key3").value(equalTo("content3")));
    }

    @Test
    void testGetValuesetNotFound() throws Exception {
        String authCertHash =
          trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(get("/valuesets/randomId")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(), authCertHash)
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), authCertSubject)
          )
          .andExpect(status().isNotFound());
    }
}
