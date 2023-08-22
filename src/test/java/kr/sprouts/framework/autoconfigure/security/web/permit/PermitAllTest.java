package kr.sprouts.framework.autoconfigure.security.web.permit;

import kr.sprouts.framework.autoconfigure.security.credential.consumer.configurations.CredentialConsumerConfiguration;
import kr.sprouts.framework.autoconfigure.security.web.application.mock.MockPermitAllTestController;
import kr.sprouts.framework.autoconfigure.security.web.configurations.SecurityWebConfiguration;
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
        MockPermitAllTestController.class
})
@Slf4j
class PermitAllTest {
    private static final String REQUEST_URI = "/mock/permit-all";
    private static final String BODY = "permitAll";

    @MockBean(name = "mvcHandlerMappingIntrospector")
    private HandlerMappingIntrospector mvcHandlerMappingIntrospector;
    private final MockMvc mockMvc;

    @Autowired
    public PermitAllTest(MockMvc mockMvc) {
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
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string(BODY));
    }

    @Test
    void put() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.PUT, REQUEST_URI))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string(BODY));
    }

    @Test
    void patch() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.PATCH, REQUEST_URI))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string(BODY));
    }

    @Test
    void delete() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.DELETE, REQUEST_URI))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string(BODY));
    }

    @Test
    void getExt() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.GET, REQUEST_URI + "/ext"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string(BODY));
    }
}
