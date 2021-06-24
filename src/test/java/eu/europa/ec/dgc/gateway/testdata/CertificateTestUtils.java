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

package eu.europa.ec.dgc.gateway.testdata;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import eu.europa.ec.dgc.gateway.connector.model.ValidationRule;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;

public class CertificateTestUtils {

    public static ValidationRule getDummyValidationRule() {
        ValidationRule validationRule = new ValidationRule();

        JsonNodeFactory jsonNodeFactory = JsonNodeFactory.instance;

        validationRule.setLogic(jsonNodeFactory.objectNode().set("field1", jsonNodeFactory.textNode("value1")));
        validationRule.setValidTo(ZonedDateTime.now().plus(1, ChronoUnit.WEEKS));
        validationRule.setValidFrom(ZonedDateTime.now().plus(3, ChronoUnit.DAYS));
        validationRule.setCertificateType("Vaccination");
        validationRule.setDescription(List.of(new ValidationRule.DescriptionItem("en", "de".repeat(10))));
        validationRule.setEngine("CERTLOGIC");
        validationRule.setEngineVersion("1.0.0");
        validationRule.setVersion("1.0.0");
        validationRule.setAffectedFields(List.of("AB", "DE"));
        validationRule.setRegion("BW");
        validationRule.setSchemaVersion("1.0.0");
        validationRule.setType("Acceptance");
        validationRule.setIdentifier("GR-EU-0001");
        validationRule.setCountry("EU");

        return validationRule;
    }

    public static X509Certificate generateCertificate(KeyPair keyPair, String country, String commonName) throws Exception {
        Date validFrom = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date validTo = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        return generateCertificate(keyPair, country, commonName, validFrom, validTo);
    }

    public static X509Certificate generateCertificate(KeyPair keyPair, String country, String commonName, X509Certificate ca, PrivateKey caKey) throws Exception {
        Date validFrom = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date validTo = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        return generateCertificate(keyPair, country, commonName, validFrom, validTo, ca, caKey);
    }

    public static X509Certificate generateCertificate(KeyPair keyPair, String country, String commonName, Date validFrom, Date validTo) throws Exception {
        X500Name subject = new X500NameBuilder()
            .addRDN(X509ObjectIdentifiers.countryName, country)
            .addRDN(X509ObjectIdentifiers.commonName, commonName)
            .build();

        BigInteger certSerial = new BigInteger(Long.toString(System.currentTimeMillis()));

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder =
            new JcaX509v3CertificateBuilder(subject, certSerial, validFrom, validTo, subject, keyPair.getPublic());

        BasicConstraints basicConstraints = new BasicConstraints(false);
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    public static X509Certificate generateCertificate(KeyPair keyPair, String country, String commonName, Date validFrom, Date validTo, X509Certificate ca, PrivateKey caKey) throws Exception {
        X500Name subject = new X500NameBuilder()
            .addRDN(X509ObjectIdentifiers.countryName, country)
            .addRDN(X509ObjectIdentifiers.commonName, commonName)
            .build();

        X500Name issuer = new X509CertificateHolder(ca.getEncoded()).getSubject();

        BigInteger certSerial = new BigInteger(Long.toString(System.currentTimeMillis()));

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKey);

        JcaX509v3CertificateBuilder certBuilder =
            new JcaX509v3CertificateBuilder(issuer, certSerial, validFrom, validTo, subject, keyPair.getPublic());

        BasicConstraints basicConstraints = new BasicConstraints(false);
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    public static void assertEquals(ValidationRule v1, ValidationRule v2) {
        Assertions.assertEquals(v1.getIdentifier(), v2.getIdentifier());
        Assertions.assertEquals(v1.getType(), v2.getType());
        Assertions.assertEquals(v1.getCountry(), v2.getCountry());
        Assertions.assertEquals(v1.getRegion(), v2.getRegion());
        Assertions.assertEquals(v1.getVersion(), v2.getVersion());
        Assertions.assertEquals(v1.getSchemaVersion(), v2.getSchemaVersion());
        Assertions.assertEquals(v1.getEngine(), v2.getEngine());
        Assertions.assertEquals(v1.getEngineVersion(), v2.getEngineVersion());
        Assertions.assertEquals(v1.getCertificateType(), v2.getCertificateType());
        Assertions.assertEquals(v1.getDescription(), v2.getDescription());
        Assertions.assertEquals(v1.getValidFrom().toEpochSecond(), v2.getValidFrom().toEpochSecond());
        Assertions.assertEquals(v1.getValidTo().toEpochSecond(), v2.getValidTo().toEpochSecond());
        Assertions.assertEquals(v1.getAffectedFields(), v2.getAffectedFields());
        Assertions.assertEquals(v1.getLogic(), v2.getLogic());
    }

}
