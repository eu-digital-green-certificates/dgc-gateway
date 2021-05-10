package eu.europa.ec.dgc.gateway.config;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BouncyCastleConfig {

    public BouncyCastleConfig() {
        Security.addProvider(new BouncyCastleProvider());
    }
}
