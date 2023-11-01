package kr.sprouts.framework.autoconfigure.security.credential.consumer.configurations;

import kr.sprouts.framework.autoconfigure.security.credential.consumer.components.CredentialConsumerManager;
import kr.sprouts.framework.autoconfigure.security.credential.consumer.properties.CredentialConsumerConfigurationProperty;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

@AutoConfiguration
@ComponentScan(basePackageClasses = { CredentialConsumerManager.class })
@EnableConfigurationProperties(value = { CredentialConsumerConfigurationProperty.class })
@Slf4j
@Getter
public class CredentialConsumerConfiguration {
    private final CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty;

    public CredentialConsumerConfiguration(CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty) {
        this.credentialConsumerConfigurationProperty = credentialConsumerConfigurationProperty;

        if (log.isInfoEnabled()) log.info("Initialized {}", CredentialConsumerConfiguration.class.getSimpleName());
    }
}
