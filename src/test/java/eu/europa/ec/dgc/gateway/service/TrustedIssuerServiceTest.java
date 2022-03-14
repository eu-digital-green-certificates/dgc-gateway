package eu.europa.ec.dgc.gateway.service;


import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedIssuerRepository;
import eu.europa.ec.dgc.gateway.testdata.TrustedIssuerTestHelper;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

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