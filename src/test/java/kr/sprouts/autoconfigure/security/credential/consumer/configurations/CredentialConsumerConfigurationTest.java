package kr.sprouts.autoconfigure.security.credential.consumer.configurations;

import kr.sprouts.autoconfigure.security.credential.consumer.components.CredentialConsumerManager;
import kr.sprouts.autoconfigure.security.credential.consumer.properties.CredentialConsumerConfigurationProperty;
import kr.sprouts.framework.autoconfigure.security.credential.provider.components.ApiKeyCredentialProvider;
import kr.sprouts.framework.autoconfigure.security.credential.provider.components.ApiKeySubject;
import kr.sprouts.framework.autoconfigure.security.credential.provider.components.BearerTokenCredentialProvider;
import kr.sprouts.framework.autoconfigure.security.credential.provider.components.BearerTokenSubject;
import kr.sprouts.framework.autoconfigure.security.credential.provider.components.CredentialProviderManager;
import kr.sprouts.framework.autoconfigure.security.credential.provider.configurations.CredentialProviderConfiguration;
import kr.sprouts.framework.library.security.credential.Credential;
import kr.sprouts.framework.library.security.credential.CredentialConsumer;
import kr.sprouts.framework.library.security.credential.CredentialConsumerSpec;
import kr.sprouts.framework.library.security.credential.CredentialHeaderSpec;
import kr.sprouts.framework.library.security.credential.CredentialProvider;
import kr.sprouts.framework.library.security.credential.Principal;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
class CredentialConsumerConfigurationTest {
    private final ApplicationContextRunner applicationContextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    CredentialConsumerConfiguration.class,
                    CredentialProviderConfiguration.class
            ));

    @Test
    void configuration() {
        String[] properties = {
                "sprouts.security.credential.header.provider-header-name=Authorization-Provider",
                "sprouts.security.credential.header.consumer-header-name=Authorization-Consumer",
                "sprouts.security.credential.header.value-header-name=Authorization",

                "sprouts.security.credential.providers[0].id=98c73526-7b15-4e0c-aacd-a47816efaedc",
                "sprouts.security.credential.providers[0].name=Provider #1",
                "sprouts.security.credential.providers[0].type=API_KEY",
                "sprouts.security.credential.providers[0].algorithm=AES128",
                "sprouts.security.credential.providers[0].codec=BASE64_URL",
                "sprouts.security.credential.providers[0].encodedSecret=ptRxQCz0a-Ug9Fiu_A2-0A==",
                "sprouts.security.credential.providers[0].targetConsumers[0].id=bcb7f865-319b-4668-9fca-4ea4440822e2",
                "sprouts.security.credential.providers[0].targetConsumers[0].name=Consumer #1",

                "sprouts.security.credential.consumers[0].id=bcb7f865-319b-4668-9fca-4ea4440822e2",
                "sprouts.security.credential.consumers[0].name=Consumer #1",
                "sprouts.security.credential.consumers[0].type=API_KEY",
                "sprouts.security.credential.consumers[0].algorithm=AES128",
                "sprouts.security.credential.consumers[0].codec=BASE64_URL",
                "sprouts.security.credential.consumers[0].encodedSecret=ptRxQCz0a-Ug9Fiu_A2-0A==",
                "sprouts.security.credential.consumers[0].validProviders[0].id=98c73526-7b15-4e0c-aacd-a47816efaedc",
                "sprouts.security.credential.consumers[0].validProviders[0].name=Provider #1",
        };

        this.applicationContextRunner.withPropertyValues(properties).run(context-> {
            assertNotNull(CredentialConsumerConfiguration.class);
            assertNotNull(CredentialConsumerConfigurationProperty.class);
        });
    }

    @Test
    void property() {
        String[] properties = {
                "sprouts.security.credential.header.provider-header-name=Authorization-Provider",
                "sprouts.security.credential.header.consumer-header-name=Authorization-Consumer",
                "sprouts.security.credential.header.value-header-name=Authorization",

                "sprouts.security.credential.providers[0].id=98c73526-7b15-4e0c-aacd-a47816efaedc",
                "sprouts.security.credential.providers[0].name=Provider #1",
                "sprouts.security.credential.providers[0].type=API_KEY",
                "sprouts.security.credential.providers[0].algorithm=AES128",
                "sprouts.security.credential.providers[0].codec=BASE64_URL",
                "sprouts.security.credential.providers[0].encodedSecret=ptRxQCz0a-Ug9Fiu_A2-0A==",
                "sprouts.security.credential.providers[0].targetConsumers[0].id=bcb7f865-319b-4668-9fca-4ea4440822e2",
                "sprouts.security.credential.providers[0].targetConsumers[0].name=Consumer #1",

                "sprouts.security.credential.consumers[0].id=bcb7f865-319b-4668-9fca-4ea4440822e2",
                "sprouts.security.credential.consumers[0].name=Consumer #1",
                "sprouts.security.credential.consumers[0].type=API_KEY",
                "sprouts.security.credential.consumers[0].algorithm=AES128",
                "sprouts.security.credential.consumers[0].codec=BASE64_URL",
                "sprouts.security.credential.consumers[0].encodedSecret=ptRxQCz0a-Ug9Fiu_A2-0A==",
                "sprouts.security.credential.consumers[0].validProviders[0].id=98c73526-7b15-4e0c-aacd-a47816efaedc",
                "sprouts.security.credential.consumers[0].validProviders[0].name=Provider #1",
        };

        this.applicationContextRunner.withPropertyValues(properties).run(context-> {
            CredentialConsumerSpec consumerSpec = context.getBean(CredentialConsumerConfiguration.class)
                    .getCredentialConsumerConfigurationProperty()
                    .getConsumers()
                    .stream()
                    .findFirst()
                    .orElseThrow();

            assertEquals("bcb7f865-319b-4668-9fca-4ea4440822e2", consumerSpec.getId());

            CredentialHeaderSpec headerSpec = context.getBean(CredentialConsumerConfiguration.class)
                    .getCredentialConsumerConfigurationProperty()
                    .getHeader();

            assertEquals("Authorization-Provider", headerSpec.getProviderHeaderName());
            assertEquals("Authorization-Consumer", headerSpec.getConsumerHeaderName());
            assertEquals("Authorization", headerSpec.getValueHeaderName());
        });
    }

    @Test
    void provideAndConsume() {
        String[] properties = {
                "sprouts.security.credential.header.provider-header-name=Authorization-Provider",
                "sprouts.security.credential.header.consumer-header-name=Authorization-Consumer",
                "sprouts.security.credential.header.value-header-name=Authorization",

                "sprouts.security.credential.providers[0].id=98c73526-7b15-4e0c-aacd-a47816efaedc",
                "sprouts.security.credential.providers[0].name=Provider #1",
                "sprouts.security.credential.providers[0].type=API_KEY",
                "sprouts.security.credential.providers[0].algorithm=AES128",
                "sprouts.security.credential.providers[0].codec=BASE64_URL",
                "sprouts.security.credential.providers[0].encodedSecret=ptRxQCz0a-Ug9Fiu_A2-0A==",
                "sprouts.security.credential.providers[0].targetConsumers[0].id=bcb7f865-319b-4668-9fca-4ea4440822e2",
                "sprouts.security.credential.providers[0].targetConsumers[0].name=Consumer #1",

                "sprouts.security.credential.providers[1].id=fc3ddab7-3942-4cc5-aaaa-b41772c6ebac",
                "sprouts.security.credential.providers[1].name=Provider #2",
                "sprouts.security.credential.providers[1].type=API_KEY",
                "sprouts.security.credential.providers[1].algorithm=AES256",
                "sprouts.security.credential.providers[1].codec=BASE64_URL",
                "sprouts.security.credential.providers[1].encodedSecret=VhIW0Qwfqwm9KGVk6dBfyD0iBlfJSOzCofPdoxUqABg=",
                "sprouts.security.credential.providers[1].targetConsumers[0].id=70ed75d8-bfdc-4227-904f-a9d17bb9472f",
                "sprouts.security.credential.providers[1].targetConsumers[0].name=Consumer #2",

                "sprouts.security.credential.providers[2].id=1ebf4960-f935-493c-8beb-1f26376bff54",
                "sprouts.security.credential.providers[2].name=Provider #3(JWT)",
                "sprouts.security.credential.providers[2].type=BEARER_TOKEN",
                "sprouts.security.credential.providers[2].algorithm=HS256",
                "sprouts.security.credential.providers[2].codec=BASE64_URL",
                "sprouts.security.credential.providers[2].encodedSecret=9rBJxUbKuODsQmu1b5oUw5dxc8YcgGh5RnqdLV3nsRwm21UJVrrziYq1a6MM5JLm",
                "sprouts.security.credential.providers[2].targetConsumers[0].id=013a7e72-9bb4-42c6-a908-514375b4318d",
                "sprouts.security.credential.providers[2].targetConsumers[0].name=Consumer #3",

                "sprouts.security.credential.consumers[0].id=bcb7f865-319b-4668-9fca-4ea4440822e2",
                "sprouts.security.credential.consumers[0].name=Consumer #1",
                "sprouts.security.credential.consumers[0].type=API_KEY",
                "sprouts.security.credential.consumers[0].algorithm=AES128",
                "sprouts.security.credential.consumers[0].codec=BASE64_URL",
                "sprouts.security.credential.consumers[0].encodedSecret=ptRxQCz0a-Ug9Fiu_A2-0A==",
                "sprouts.security.credential.consumers[0].validProviders[0].id=98c73526-7b15-4e0c-aacd-a47816efaedc",
                "sprouts.security.credential.consumers[0].validProviders[0].name=Provider #1",

                "sprouts.security.credential.consumers[1].id=70ed75d8-bfdc-4227-904f-a9d17bb9472f",
                "sprouts.security.credential.consumers[1].name=Consumer #2",
                "sprouts.security.credential.consumers[1].type=API_KEY",
                "sprouts.security.credential.consumers[1].algorithm=AES256",
                "sprouts.security.credential.consumers[1].codec=BASE64_URL",
                "sprouts.security.credential.consumers[1].encodedSecret=VhIW0Qwfqwm9KGVk6dBfyD0iBlfJSOzCofPdoxUqABg=",
                "sprouts.security.credential.consumers[1].validProviders[0].id=fc3ddab7-3942-4cc5-aaaa-b41772c6ebac",
                "sprouts.security.credential.consumers[1].validProviders[0].name=Provider #2",

                "sprouts.security.credential.consumers[2].id=013a7e72-9bb4-42c6-a908-514375b4318d",
                "sprouts.security.credential.consumers[2].name=Consumer #3(JWT)",
                "sprouts.security.credential.consumers[2].type=BEARER_TOKEN",
                "sprouts.security.credential.consumers[2].algorithm=HS256",
                "sprouts.security.credential.consumers[2].codec=BASE64_URL",
                "sprouts.security.credential.consumers[2].encodedSecret=9rBJxUbKuODsQmu1b5oUw5dxc8YcgGh5RnqdLV3nsRwm21UJVrrziYq1a6MM5JLm",
                "sprouts.security.credential.consumers[2].validProviders[0].id=1ebf4960-f935-493c-8beb-1f26376bff54",
                "sprouts.security.credential.consumers[2].validProviders[0].name=Provider #3",
        };

        this.applicationContextRunner.withPropertyValues(properties).run(context -> {
            UUID memberId = UUID.randomUUID();
            Long validityInMinutes = 60L;

            for (CredentialProvider<?> provider : context.getBean(CredentialProviderManager.class).getValues().orElseThrow()) {
                Credential credential = null;

                if (provider instanceof ApiKeyCredentialProvider) {
                    credential = ((ApiKeyCredentialProvider) provider).provide(ApiKeySubject.of(memberId));
                } else if (provider instanceof BearerTokenCredentialProvider) {
                    credential = ((BearerTokenCredentialProvider) provider).provide(BearerTokenSubject.of(memberId, validityInMinutes));
                }

                assertNotNull(credential);

                CredentialConsumer<?> consumer = context.getBean(CredentialConsumerManager.class).get(credential.getConsumerIds().stream().findFirst().orElseThrow()).orElseThrow();

                Principal<?> principal = consumer.consume(credential);

                assertNotNull(principal);
            }
        });
    }
}
