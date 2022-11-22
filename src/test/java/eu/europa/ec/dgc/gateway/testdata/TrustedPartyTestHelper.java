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

package eu.europa.ec.dgc.gateway.testdata;

import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedPartyRepository;
import eu.europa.ec.dgc.signing.SignedCertificateMessageBuilder;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TrustedPartyTestHelper {

    private final Map<TrustedPartyEntity.CertificateType, Map<String, String>> hashMap = Map.of(
        TrustedPartyEntity.CertificateType.AUTHENTICATION, new HashMap<>(),
        TrustedPartyEntity.CertificateType.CSCA, new HashMap<>(),
        TrustedPartyEntity.CertificateType.UPLOAD, new HashMap<>()
    );

    private final Map<TrustedPartyEntity.CertificateType, Map<String, X509Certificate>> certificateMap = Map.of(
        TrustedPartyEntity.CertificateType.AUTHENTICATION, new HashMap<>(),
        TrustedPartyEntity.CertificateType.CSCA, new HashMap<>(),
        TrustedPartyEntity.CertificateType.UPLOAD, new HashMap<>()
    );

    private final Map<TrustedPartyEntity.CertificateType, Map<String, PrivateKey>> privateKeyMap = Map.of(
        TrustedPartyEntity.CertificateType.AUTHENTICATION, new HashMap<>(),
        TrustedPartyEntity.CertificateType.CSCA, new HashMap<>(),
        TrustedPartyEntity.CertificateType.UPLOAD, new HashMap<>()
    );

    private final TrustedPartyRepository trustedPartyRepository;

    private final CertificateUtils certificateUtils;

    private final DgcTestKeyStore testKeyStore;

    public X509Certificate getTestCert(String testCertId, TrustedPartyEntity.CertificateType type,
                                       String countryCode, ZonedDateTime createdAt) throws Exception {
        return createAndInsertCert(testCertId, type, countryCode, createdAt);
    }

    public String getHash(TrustedPartyEntity.CertificateType type, String countryCode) throws Exception {
        prepareTestCert(type, countryCode);
        return hashMap.get(type).get(countryCode);
    }

    public X509Certificate getCert(TrustedPartyEntity.CertificateType type, String countryCode) throws Exception {
        prepareTestCert(type, countryCode);
        return certificateMap.get(type).get(countryCode);
    }

    public PrivateKey getPrivateKey(TrustedPartyEntity.CertificateType type, String countryCode) throws Exception {
        prepareTestCert(type, countryCode);
        return privateKeyMap.get(type).get(countryCode);
    }

    public void setRoles(String countryCode, TrustedPartyEntity.CertificateRoles... roles) throws Exception {
        String hash = getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, countryCode);

        TrustedPartyEntity entity = trustedPartyRepository.getFirstByThumbprintAndCertificateType(
            hash, TrustedPartyEntity.CertificateType.AUTHENTICATION).orElseThrow();

        entity.setCertificateRoles(Arrays.asList(roles));

        trustedPartyRepository.save(entity);
    }

    public void clear(TrustedPartyEntity.CertificateType type, String countryCode) {
        certificateMap.get(type).remove(countryCode);
        hashMap.get(type).remove(countryCode);
        privateKeyMap.get(type).remove(countryCode);
    }

    private void prepareTestCert(TrustedPartyEntity.CertificateType type, String countryCode) throws Exception {
        // Check if a test certificate already exists
        if (!hashMap.get(type).containsKey(countryCode)) {
            createAndInsertCert(type, countryCode);
        }

        // Check if generated certificate is (still) present in DB
        if (trustedPartyRepository.getFirstByThumbprintAndCertificateType(
            hashMap.get(type).get(countryCode), type
        ).isEmpty()) {
            insertCert(type, countryCode, null, certificateMap.get(type).get(countryCode));
        }
    }

    private void createAndInsertCert(TrustedPartyEntity.CertificateType type, String countryCode) throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate authCertificate =
            CertificateTestUtils.generateCertificate(keyPair, countryCode,
                "DGC Test " + type.name() + " Cert");

        certificateMap.get(type).put(countryCode, authCertificate);
        hashMap.get(type).put(countryCode, certificateUtils.getCertThumbprint(authCertificate));
        privateKeyMap.get(type).put(countryCode, keyPair.getPrivate());

        insertCert(type, countryCode, null, authCertificate);
    }

    private X509Certificate createAndInsertCert(String testCertId, TrustedPartyEntity.CertificateType type,
                                                String countryCode, ZonedDateTime createdAt) throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate authCertificate =
            CertificateTestUtils.generateCertificate(keyPair, countryCode,
                "DGC Test " + type.name() + " Cert-" + testCertId);

        return insertCert(type, countryCode, createdAt, authCertificate);
    }

    private X509Certificate insertCert(TrustedPartyEntity.CertificateType type, String countryCode,
                                       ZonedDateTime createdAt, X509Certificate authCertificate) throws Exception {

        String certRawData = Base64.getEncoder().encodeToString(authCertificate.getEncoded());
        String certHash = certificateUtils.getCertThumbprint(authCertificate);

        String signature = new SignedCertificateMessageBuilder()
            .withPayload(new X509CertificateHolder(authCertificate.getEncoded()))
            .withSigningCertificate(new X509CertificateHolder(testKeyStore.getTrustAnchor().getEncoded()),
                testKeyStore.getTrustAnchorPrivateKey())
            .buildAsString(true);

        TrustedPartyEntity trustedPartyEntity = new TrustedPartyEntity();
        if (createdAt != null) {
            trustedPartyEntity.setCreatedAt(createdAt);
        }
        trustedPartyEntity.setCertificateType(type);
        trustedPartyEntity.setCountry(countryCode);
        trustedPartyEntity.setSignature(signature);
        trustedPartyEntity.setRawData(certRawData);
        trustedPartyEntity.setThumbprint(certHash);

        trustedPartyRepository.save(trustedPartyEntity);
        return authCertificate;
    }

    public String signString(final String hashdata) throws Exception {
        return new SignedStringMessageBuilder()
            .withPayload(hashdata)
            .withSigningCertificate(new X509CertificateHolder(testKeyStore.getTrustAnchor().getEncoded()),
                testKeyStore.getTrustAnchorPrivateKey())
            .buildAsString();
    }
}
