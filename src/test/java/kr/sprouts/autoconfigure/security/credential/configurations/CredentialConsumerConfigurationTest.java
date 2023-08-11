package kr.sprouts.autoconfigure.security.credential.configurations;

import kr.sprouts.autoconfigure.security.credential.properties.CredentialConsumerConfigurationProperty;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class CredentialConsumerConfigurationTest {
    Logger log = Logger.getLogger(this.getClass().getSimpleName());
    private final ApplicationContextRunner applicationContextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CredentialConsumerConfigurationTest.class));

    @Test
    void configuration() {
        String[] properties = {
                "sprouts.security.credential.providers[0].id=bcb7f865-319b-4668-9fca-4ea4440822e2",
                "sprouts.security.credential.providers[0].name=Consumer #1",
                "sprouts.security.credential.providers[0].type=API_KEY",
                "sprouts.security.credential.providers[0].algorithm=AES128",
                "sprouts.security.credential.providers[0].codec=BASE64_URL",
                "sprouts.security.credential.providers[0].encodedSecret=ptRxQCz0a-Ug9Fiu_A2-0A==",
                "sprouts.security.credential.providers[0].validProviders[0].id=98c73526-7b15-4e0c-aacd-a47816efaedc",
                "sprouts.security.credential.providers[0].validProviders[0].name=Provider #1",
                "sprouts.security.credential.providers[0].validProviders[1].id=fc3ddab7-3942-4cc5-aaaa-b41772c6ebac",
                "sprouts.security.credential.providers[0].validProviders[1].name=Provider #2",
        };

        this.applicationContextRunner.withPropertyValues(properties).run(context-> {
            assertNotNull(CredentialConsumerConfiguration.class);
            assertNotNull(CredentialConsumerConfigurationProperty.class);
        });
    }
}
