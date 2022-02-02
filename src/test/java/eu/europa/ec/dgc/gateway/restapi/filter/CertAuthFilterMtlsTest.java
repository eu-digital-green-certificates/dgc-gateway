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

package eu.europa.ec.dgc.gateway.restapi.filter;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedPartyRepository;
import eu.europa.ec.dgc.gateway.service.TrustedPartyService;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("mtls")
class CertAuthFilterMtlsTest {

    @Autowired
    private TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    private TrustedPartyService trustedPartyService;

    @Autowired
    private TrustedPartyRepository trustedPartyRepository;

    @Autowired
    MockMvc mockMvc;

    private final String countryCode = "EU";

    @Test
    void testFilterShouldAppendCountryAndThumbprintToRequestObjectFrommTLSCert() throws Exception {
        String certHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .with(x509(trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode)))
            .contentType("application/cms")
        ).andExpect(mvcResult -> {
            Assertions.assertEquals(countryCode, mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY));
            Assertions.assertEquals(
                certHash,
                mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT)
            );
        });
    }

    @Test
    void testAccessDeniedIfClientCertIsNotWhitelisted() throws Exception {
        X509Certificate certificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        TrustedPartyEntity entity = trustedPartyService.getCertificate(
            trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode),
            countryCode,
            TrustedPartyEntity.CertificateType.AUTHENTICATION
        ).orElseThrow();
        trustedPartyRepository.delete(entity);

        mockMvc.perform(post("/signerCertificate/")
            .with(x509(certificate))
            .contentType("application/cms")
        ).andExpect(status().isUnauthorized());
    }
}

