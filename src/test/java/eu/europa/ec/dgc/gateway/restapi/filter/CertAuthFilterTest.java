/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class CertAuthFilterTest {

    @Autowired
    private DgcConfigProperties properties;

    @Autowired
    private TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    MockMvc mockMvc;

    private final String countryCode = "EU";
    private final String authDn = "C=" + countryCode;

    @Test
    void testRequestShouldFailIfDNHeaderIsMissing() throws Exception {
        String certHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
            .header(properties.getCertAuth().getHeaderFields().getThumbprint(), certHash)
        ).andExpect(status().isForbidden());
    }

    @Test
    void testRequestShouldFailIfThumbprintHeaderIsMissing() throws Exception {
        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
            .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), authDn)
        ).andExpect(status().isForbidden());
    }

    @Test
    void testRequestShouldFailIfCertHeadersAreMissing() throws Exception {
        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
        ).andExpect(status().isForbidden());
    }

    @Test
    void testRequestShouldFailIfCertIsNotOnWhitelist() throws Exception {
        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
            .header(properties.getCertAuth().getHeaderFields().getThumbprint(), "randomString")
            .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), authDn)
        ).andExpect(status().isForbidden());
    }

    @Test
    void testFilterShouldAppendCountryAndThumbprintToRequestObject() throws Exception {
        String certHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
            .header(properties.getCertAuth().getHeaderFields().getThumbprint(), certHash)
            .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), authDn)
        ).andExpect(mvcResult -> {
            Assertions.assertEquals("EU", mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY));
            Assertions.assertEquals(
                certHash,
                mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT)
            );
        });
    }

    @Test
    void testFilterShouldDecodeDnString() throws Exception {
        String encodedDnString = "ST%3dSome-State%2c%20C%3dEU%2c%20O%3dInternet%20Widgits%20Pty%20Ltd%2c%20CN%3dTest%20Cert";

        String certHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
            .header(properties.getCertAuth().getHeaderFields().getThumbprint(), certHash)
            .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), encodedDnString)
        ).andExpect(mvcResult -> {
            Assertions.assertEquals("EU", mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY));
            Assertions.assertEquals(
                certHash,
                mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT)
            );
        });
    }

    @Test
    void testFilterShouldDecodeBase64AndUrlEncodedCertThumbprint() throws Exception {
        String certHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        byte[] certHashBytes = new BigInteger(certHash, 16).toByteArray();

        if (certHashBytes[0] == 0) {
            byte[] truncatedCertHashBytes = new byte[certHashBytes.length - 1];
            System.arraycopy(certHashBytes, 1, truncatedCertHashBytes, 0, truncatedCertHashBytes.length);
            certHashBytes = truncatedCertHashBytes;
        }

        String encodedThumbprint =
            URLEncoder.encode(Base64.getEncoder().encodeToString(certHashBytes), StandardCharsets.UTF_8);

        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
            .header(properties.getCertAuth().getHeaderFields().getThumbprint(), encodedThumbprint)
            .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), "O=Test Firma GmbH,C=EU,U=,TR,TT=43")
        ).andExpect(mvcResult -> {
            Assertions.assertEquals("EU", mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY));
            Assertions.assertEquals(
                certHash,
                mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT)
            );
        });
    }

    @Test
    void testFilterShouldDecodeBase64EncodedCertThumbprint() throws Exception {
        String certHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);
        byte[] certHashBytes = new BigInteger(certHash, 16).toByteArray();

        if (certHashBytes[0] == 0) {
            byte[] truncatedCertHashBytes = new byte[certHashBytes.length - 1];
            System.arraycopy(certHashBytes, 1, truncatedCertHashBytes, 0, truncatedCertHashBytes.length);
            certHashBytes = truncatedCertHashBytes;
        }

        String encodedThumbprint = Base64.getEncoder().encodeToString(certHashBytes);

        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
            .header(properties.getCertAuth().getHeaderFields().getThumbprint(), encodedThumbprint)
            .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), "O=Test Firma GmbH,C=EU,U=,TR,TT=43")
        ).andExpect(mvcResult -> {
            Assertions.assertEquals("EU", mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY));
            Assertions.assertEquals(
                certHash,
                mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT)
            );
        });
    }


    @Test
    void testRequestShouldFailIfCountryIsNotPresentInDnString() throws Exception {
        String certHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
            .header(properties.getCertAuth().getHeaderFields().getThumbprint(), certHash)
            .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), "O=Test Firma GmbH,U=Abteilung XYZ,TR=test")
        ).andExpect(status().isBadRequest());
    }

    @Test
    void testFilterShouldFindCountryEvenOnMalformedDnString() throws Exception {
        String certHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
            .header(properties.getCertAuth().getHeaderFields().getThumbprint(), certHash)
            .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), "O=Test Firma GmbH,C=EU,U=,TR,TT=43")
        ).andExpect(mvcResult -> Assertions.assertEquals("EU", mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY)));
    }

    @Test
    void testRequestShouldNotFailIfDnStringContainsDuplicatedKeys() throws Exception {
        String certHash = trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        mockMvc.perform(post("/signerCertificate/")
            .contentType("application/cms")
            .header(properties.getCertAuth().getHeaderFields().getThumbprint(), certHash)
            .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), "O=Test Firma GmbH,O=XXX,C=EU,U=Abteilung XYZ,TR=test")
        ).andExpect(mvcResult -> Assertions.assertEquals("EU", mvcResult.getRequest().getAttribute(CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY)));
    }
}

