package kr.sprouts.autoconfigure.security.credential.configurations;

import kr.sprouts.autoconfigure.security.credential.consumers.CredentialConsumerManager;
import kr.sprouts.autoconfigure.security.credential.properties.CredentialConsumerConfigurationProperty;
import lombok.Getter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import java.util.logging.Level;
import java.util.logging.Logger;

@Configuration
@ComponentScan(basePackageClasses = { CredentialConsumerManager.class })
@EnableConfigurationProperties(value = { CredentialConsumerConfigurationProperty.class })
public class CredentialConsumerConfiguration {
    private final Logger log = Logger.getLogger(this.getClass().getSimpleName());

    @Getter
    private final CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty;

    public CredentialConsumerConfiguration(CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty) {
        this.credentialConsumerConfigurationProperty = credentialConsumerConfigurationProperty;

        if (log.isLoggable(Level.INFO)) {
            log.info(String.format("Initialize %s", this.getClass().getSimpleName()));
        }
    }
}
