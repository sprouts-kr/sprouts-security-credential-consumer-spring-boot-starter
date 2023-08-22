package kr.sprouts.autoconfigure.security.credential.consumers;

import kr.sprouts.autoconfigure.security.credential.properties.CredentialConsumerConfigurationProperty;
import kr.sprouts.framework.library.security.credential.CredentialConsumer;
import kr.sprouts.framework.library.security.credential.CredentialConsumerSpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Component
@Slf4j
public class CredentialConsumerManager {
    private final Map<UUID, CredentialConsumer<?>> credentialConsumers;

    public CredentialConsumerManager(CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty) {
        if (credentialConsumerConfigurationProperty == null
                || credentialConsumerConfigurationProperty.getConsumers() == null
                || credentialConsumerConfigurationProperty.getConsumers().isEmpty()
        ) throw new InitializeCredentialConsumerException();

        credentialConsumers = new HashMap<>();

        for (CredentialConsumerSpec credentialConsumerSpec : credentialConsumerConfigurationProperty.getConsumers()) {
            switch (credentialConsumerSpec.getType().toUpperCase()) {
                case "API_KEY":
                    credentialConsumers.put(UUID.fromString(credentialConsumerSpec.getId()), ApiKeyCredentialConsumer.of(credentialConsumerSpec));
                    break;
                case "BEARER_TOKEN":
                    credentialConsumers.put(UUID.fromString(credentialConsumerSpec.getId()), BearerTokenCredentialConsumer.of(credentialConsumerSpec));
                    break;
                default:
                    throw new UnsupportedCredentialConsumerException();
            }

            if (log.isInfoEnabled()) log.info("Initialized credential consumer. Id: {}, Name: {}", credentialConsumerSpec.getId(), credentialConsumerSpec.getName());
        }
    }

    public Optional<Collection<CredentialConsumer<?>>> getValues() {
        return Optional.of(credentialConsumers.values());
    }

    public Optional<CredentialConsumer<?>> get(UUID consumerId) {
        return Optional.of(credentialConsumers.get(consumerId));
    }
}
