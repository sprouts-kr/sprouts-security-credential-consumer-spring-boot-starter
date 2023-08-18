package kr.sprouts.autoconfigure.security.web.configurations;

import kr.sprouts.autoconfigure.security.credential.configurations.CredentialConsumerConfiguration;
import kr.sprouts.autoconfigure.security.credential.properties.CredentialConsumerConfigurationProperty;
import kr.sprouts.autoconfigure.security.web.properties.SecurityHttpPermitProperty;
import kr.sprouts.autoconfigure.security.web.properties.SecurityWebIgnoreProperty;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ActiveProfiles(value = "test")
@AutoConfigureMockMvc
@SpringBootTest(classes = {
        CredentialConsumerConfiguration.class,
        SecurityWebConfiguration.class
})
class SecurityWebConfigurationTest {
    private Logger log = Logger.getLogger(SecurityWebConfigurationTest.class.getCanonicalName());
    private final WebApplicationContext context;

    @MockBean(name = "mvcHandlerMappingIntrospector")
    private HandlerMappingIntrospector mvcHandlerMappingIntrospector;

    @Autowired
    public SecurityWebConfigurationTest(MockMvc mockMvc) {
        this.context = mockMvc.getDispatcherServlet().getWebApplicationContext();
    }

    @Test
    void property() {
        assertNotNull(context);

        CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty = context.getBean(CredentialConsumerConfigurationProperty.class);

        assertNotNull(credentialConsumerConfigurationProperty);
        assertNotNull(credentialConsumerConfigurationProperty.getHeader());
        assertNotNull(credentialConsumerConfigurationProperty.getConsumers());

        SecurityHttpPermitProperty securityHttpPermitProperty = context.getBean(SecurityHttpPermitProperty.class);

        assertNotNull(securityHttpPermitProperty);

        SecurityWebIgnoreProperty securityWebIgnoreProperty = context.getBean(SecurityWebIgnoreProperty.class);

        assertNotNull(securityWebIgnoreProperty);

        // credential header
        assertEquals("Authorization-Provider", credentialConsumerConfigurationProperty.getHeader().getProviderHeaderName());
        assertEquals("Authorization-Consumer", credentialConsumerConfigurationProperty.getHeader().getConsumerHeaderName());
        assertEquals("Authorization", credentialConsumerConfigurationProperty.getHeader().getValueHeaderName());

        // size of credential consumers
        assertEquals(3, credentialConsumerConfigurationProperty.getConsumers().size());

        // size of http authorize request patterns
        assertEquals(1, securityHttpPermitProperty.getPermitAll().getPatterns().size());
        assertEquals(1, securityHttpPermitProperty.getPermitGet().getPatterns().size());
        assertEquals(1, securityHttpPermitProperty.getPermitPost().getPatterns().size());
        assertEquals(1, securityHttpPermitProperty.getPermitPut().getPatterns().size());
        assertEquals(1, securityHttpPermitProperty.getPermitPatch().getPatterns().size());
        assertEquals(0, securityHttpPermitProperty.getPermitDelete().getPatterns().size());

        // size of web ignore patterns
        assertEquals(1, securityWebIgnoreProperty.getIgnore().getPatterns().size());
    }
}
