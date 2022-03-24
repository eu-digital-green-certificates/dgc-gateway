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

package eu.europa.ec.dgc.gateway.testdata;

import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Profile("!int-test")
public class TrustedIssuerTestHelper {

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    public TrustedIssuerEntity createTrustedIssuer(final String country) throws Exception {
        TrustedIssuerEntity trustedIssuer = new TrustedIssuerEntity();
        trustedIssuer.setUrl("https://trusted.issuer");
        trustedIssuer.setName("tiName");
        trustedIssuer.setCountry(country);
        trustedIssuer.setUrlType(TrustedIssuerEntity.UrlType.HTTP);
        trustedIssuer.setSslPublicKey("pubKey");
        trustedIssuer.setThumbprint("thumbprint");
        trustedIssuer.setKeyStorageType("JWKS");
        final String signature = trustedPartyTestHelper.signString(getHashData(trustedIssuer));
        trustedIssuer.setSignature(signature);

        return trustedIssuer;
    }

    private String getHashData(TrustedIssuerEntity entity) {
        return entity.getCountry() + ";"
                + entity.getName() + ";"
                + entity.getUrl() + ";"
                + entity.getUrlType().name() + ";";
    }
}
