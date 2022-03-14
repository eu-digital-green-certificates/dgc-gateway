package eu.europa.ec.dgc.gateway.testdata;

import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
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
