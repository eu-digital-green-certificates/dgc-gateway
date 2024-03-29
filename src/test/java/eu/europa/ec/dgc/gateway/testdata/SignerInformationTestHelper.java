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

import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SignerInformationTestHelper {

    private final SignerInformationRepository signerInformationRepository;

    private final CertificateUtils certificateUtils;

    public void createSignerInformationInDB(String countryCode, String signature,
                                            X509Certificate certificate, ZonedDateTime createdAt) throws Exception {
        createSignerInformationInDB(countryCode, signature, certificate, createdAt, null);
    }

    public void createSignerInformationInDB(String countryCode, String signature,
                                            X509Certificate certificate, ZonedDateTime createdAt,
                                            ZonedDateTime deletedAt) throws Exception {
        signerInformationRepository.save(new SignerInformationEntity(
            null,
            createdAt,
            deletedAt,
            countryCode,
            certificateUtils.getCertThumbprint(certificate),
            Base64.getEncoder().encodeToString(certificate.getEncoded()),
            deletedAt == null ? signature : null,
            SignerInformationEntity.CertificateType.DSC
        ));
    }
}
