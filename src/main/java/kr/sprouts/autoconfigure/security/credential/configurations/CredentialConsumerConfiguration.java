package kr.sprouts.autoconfigure.security.credential.configurations;

import kr.sprouts.autoconfigure.security.credential.consumers.CredentialConsumerManager;
import kr.sprouts.autoconfigure.security.credential.properties.CredentialConsumerConfigurationProperty;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackageClasses = { CredentialConsumerManager.class })
@EnableConfigurationProperties(value = { CredentialConsumerConfigurationProperty.class })
@Slf4j
@Getter
public class CredentialConsumerConfiguration {
    private final CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty;

    public CredentialConsumerConfiguration(CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty) {
        this.credentialConsumerConfigurationProperty = credentialConsumerConfigurationProperty;

        if (log.isInfoEnabled()) log.info("Initialized CredentialConsumerConfiguration");
    }
}
