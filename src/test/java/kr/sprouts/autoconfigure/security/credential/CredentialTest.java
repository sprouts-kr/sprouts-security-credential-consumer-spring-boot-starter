package kr.sprouts.autoconfigure.security.credential;

import kr.sprouts.autoconfigure.security.credential.application.mock.CredentialTestController;
import kr.sprouts.autoconfigure.security.credential.configurations.CredentialConsumerConfiguration;
import kr.sprouts.autoconfigure.security.credential.configurations.CredentialProviderConfiguration;
import kr.sprouts.autoconfigure.security.credential.properties.CredentialConsumerConfigurationProperty;
import kr.sprouts.autoconfigure.security.credential.providers.ApiKeyCredentialProvider;
import kr.sprouts.autoconfigure.security.credential.providers.ApiKeySubject;
import kr.sprouts.autoconfigure.security.credential.providers.BearerTokenCredentialProvider;
import kr.sprouts.autoconfigure.security.credential.providers.BearerTokenSubject;
import kr.sprouts.autoconfigure.security.credential.providers.CredentialProviderManager;
import kr.sprouts.autoconfigure.security.web.configurations.SecurityWebConfiguration;
import kr.sprouts.security.credential.Credential;
import kr.sprouts.security.credential.CredentialHeaderSpec;
import kr.sprouts.security.credential.CredentialProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpMethod;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.UUID;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@ActiveProfiles(value = "test")
@AutoConfigureMockMvc
@SpringBootTest(classes = {
        CredentialProviderConfiguration.class,
        CredentialProviderManager.class,
        CredentialConsumerConfiguration.class,
        SecurityWebConfiguration.class,
        CredentialTestController.class
})
class CredentialTest {
    private Logger log = Logger.getLogger(CredentialTest.class.getCanonicalName());

    private static final String SEPARATOR_CHARS = ",";

    private static final String BODY = "credential";

    @MockBean(name = "mvcHandlerMappingIntrospector")
    private HandlerMappingIntrospector mvcHandlerMappingIntrospector;
    private final MockMvc mockMvc;
    private final CredentialProviderManager credentialProviderManager;

    private final CredentialHeaderSpec credentialHeaderSpec;

    @Autowired
    public CredentialTest(MockMvc mockMvc, CredentialProviderManager credentialProviderManager, CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty) {
        this.mockMvc = mockMvc;
        this.credentialProviderManager = credentialProviderManager;
        this.credentialHeaderSpec = credentialConsumerConfigurationProperty.getHeader();
    }

    @Test
    void requestWithValidCredential() throws Exception {
        String providerHeaderName = credentialHeaderSpec.getProviderHeaderName();
        String consumerHeaderName = credentialHeaderSpec.getConsumerHeaderName();
        String valueHeaderName = credentialHeaderSpec.getValueHeaderName();

        UUID memberId = UUID.randomUUID();
        Long validityInMinutes = 60L;

        for(CredentialProvider<?> credentialProvider : credentialProviderManager.getValues().orElseThrow()) {
            Credential credential = null;

            if (credentialProvider instanceof ApiKeyCredentialProvider) {
                credential = ((ApiKeyCredentialProvider) credentialProvider).provide(ApiKeySubject.of(memberId));
            } else if (credentialProvider instanceof BearerTokenCredentialProvider) {
                credential = ((BearerTokenCredentialProvider) credentialProvider).provide(BearerTokenSubject.of(memberId, validityInMinutes));
            }

            assertNotNull(credential);

            mockMvc.perform(MockMvcRequestBuilders
                            .request(HttpMethod.GET, "/mock/credential")
                            .header(providerHeaderName, credential.getProviderId())
                            .header(consumerHeaderName, credential.getConsumerIds().stream().map(UUID::toString).collect(Collectors.joining(SEPARATOR_CHARS)))
                            .header(valueHeaderName, credential.getValue()))
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(MockMvcResultMatchers.content().string(BODY))
            ;
        }
    }

    @Test
    void requestWithInvalidCredential() throws Exception {
        String providerHeaderName = credentialHeaderSpec.getProviderHeaderName();
        String consumerHeaderName = credentialHeaderSpec.getConsumerHeaderName();
        String valueHeaderName = credentialHeaderSpec.getValueHeaderName();

        UUID memberId = UUID.randomUUID();
        Long validityInMinutes = 60L;

        for(CredentialProvider<?> credentialProvider : credentialProviderManager.getValues().orElseThrow()) {
            Credential credential = null;

            if (credentialProvider instanceof ApiKeyCredentialProvider) {
                credential = ((ApiKeyCredentialProvider) credentialProvider).provide(ApiKeySubject.of(memberId));
            } else if (credentialProvider instanceof BearerTokenCredentialProvider) {
                credential = ((BearerTokenCredentialProvider) credentialProvider).provide(BearerTokenSubject.of(memberId, validityInMinutes));
            }

            assertNotNull(credential);

            mockMvc.perform(MockMvcRequestBuilders
                            .request(HttpMethod.GET, "/mock/credential")
                            .header(providerHeaderName, credential.getProviderId())
                            .header(consumerHeaderName, credential.getConsumerIds().stream().map(UUID::toString).collect(Collectors.joining(SEPARATOR_CHARS)))
                            .header(valueHeaderName, "invalid credential value."))
                    .andExpect(MockMvcResultMatchers.status().isForbidden());
        }
    }
}
