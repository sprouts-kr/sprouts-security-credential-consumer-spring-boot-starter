package kr.sprouts.autoconfigure.security.web.permit;

import kr.sprouts.autoconfigure.security.credential.consumer.configurations.CredentialConsumerConfiguration;
import kr.sprouts.autoconfigure.security.web.application.mock.MockPermitGetTestController;
import kr.sprouts.autoconfigure.security.web.configurations.SecurityWebConfiguration;
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
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@ActiveProfiles(value = "test")
@AutoConfigureMockMvc
@SpringBootTest(classes = {
        CredentialConsumerConfiguration.class,
        SecurityWebConfiguration.class,
        MockPermitGetTestController.class
})
@Slf4j
class PermitGetTest {
    private static final String REQUEST_URI = "/mock/permit-get";
    private static final String BODY = "permitGet";

    @MockBean(name = "mvcHandlerMappingIntrospector")
    private HandlerMappingIntrospector mvcHandlerMappingIntrospector;
    private final MockMvc mockMvc;

    @Autowired
    public PermitGetTest(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Test
    void get() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.GET, REQUEST_URI))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string(BODY));
    }

    @Test
    void post() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.POST, REQUEST_URI))
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }

    @Test
    void put() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.PUT, REQUEST_URI))
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }

    @Test
    void patch() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.PATCH, REQUEST_URI))
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }

    @Test
    void delete() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.DELETE, REQUEST_URI))
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }

    @Test
    void getExt() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.GET, REQUEST_URI + "/ext"))
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }
}
