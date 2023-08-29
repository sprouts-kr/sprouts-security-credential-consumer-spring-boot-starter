package kr.sprouts.framework.autoconfigure.security.credential.consumer;

import kr.sprouts.framework.autoconfigure.security.credential.consumer.application.mock.CredentialTestController;
import kr.sprouts.framework.autoconfigure.security.credential.consumer.configurations.CredentialConsumerConfiguration;
import kr.sprouts.framework.autoconfigure.security.credential.consumer.properties.CredentialConsumerConfigurationProperty;
import kr.sprouts.framework.autoconfigure.security.credential.provider.components.ApiKeyCredentialProvider;
import kr.sprouts.framework.autoconfigure.security.credential.provider.components.ApiKeySubject;
import kr.sprouts.framework.autoconfigure.security.credential.provider.components.BearerTokenCredentialProvider;
import kr.sprouts.framework.autoconfigure.security.credential.provider.components.BearerTokenSubject;
import kr.sprouts.framework.autoconfigure.security.credential.provider.components.CredentialProviderManager;
import kr.sprouts.framework.autoconfigure.security.credential.provider.configurations.CredentialProviderConfiguration;
import kr.sprouts.framework.autoconfigure.security.web.configurations.SecurityWebConfiguration;
import kr.sprouts.framework.library.security.credential.Credential;
import kr.sprouts.framework.library.security.credential.CredentialHeaderSpec;
import kr.sprouts.framework.library.security.credential.CredentialProvider;
import kr.sprouts.framework.library.security.credential.codec.CodecType;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.util.SerializationUtils;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.UUID;

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
@Slf4j
class CredentialTest {
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
        String authorizationHeader = credentialHeaderSpec.getName();
        String authorizationPrefix = credentialHeaderSpec.getPrefix();

        UUID memberId = UUID.randomUUID();
        Long validityInMinutes = 60L;

        for(CredentialProvider<?> credentialProvider : credentialProviderManager.getProviders()) {
            Credential credential = null;

            if (credentialProvider instanceof ApiKeyCredentialProvider) {
                credential = ((ApiKeyCredentialProvider) credentialProvider).provide(ApiKeySubject.of(memberId));
            } else if (credentialProvider instanceof BearerTokenCredentialProvider) {
                credential = ((BearerTokenCredentialProvider) credentialProvider).provide(BearerTokenSubject.of(memberId, validityInMinutes));
            }

            byte[] serializedCredential = SerializationUtils.serialize(credential);
            String encodedCredential = CodecType.BASE64_URL.getCodecSupplier().get().encodeToString(serializedCredential);

            assertNotNull(encodedCredential);

            mockMvc.perform(MockMvcRequestBuilders
                            .request(HttpMethod.GET, "/mock/credential")
                            .header(authorizationHeader, String.format("%s %s", authorizationPrefix, encodedCredential)))
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(MockMvcResultMatchers.content().string(BODY))
            ;
        }
    }

    @Test
    void requestWithInvalidCredential() throws Exception {
        String authorizationHeader = credentialHeaderSpec.getName();
        String authorizationPrefix = credentialHeaderSpec.getPrefix();

        UUID memberId = UUID.randomUUID();
        Long validityInMinutes = 60L;

        for(CredentialProvider<?> credentialProvider : credentialProviderManager.getProviders()) {
            Credential credential = null;

            if (credentialProvider instanceof ApiKeyCredentialProvider) {
                credential = ((ApiKeyCredentialProvider) credentialProvider).provide(ApiKeySubject.of(memberId));
            } else if (credentialProvider instanceof BearerTokenCredentialProvider) {
                credential = ((BearerTokenCredentialProvider) credentialProvider).provide(BearerTokenSubject.of(memberId, validityInMinutes));
            }

            byte[] serializedCredential = SerializationUtils.serialize(credential);
            String encodedCredential = CodecType.BASE64_URL.getCodecSupplier().get().encodeToString(serializedCredential);

            assertNotNull(encodedCredential);

            mockMvc.perform(MockMvcRequestBuilders
                            .request(HttpMethod.GET, "/mock/credential")
                            .header(authorizationHeader, String.format("%s %s", authorizationPrefix, "Invalid credential")))
                    .andExpect(MockMvcResultMatchers.status().isForbidden());
        }
    }
}
