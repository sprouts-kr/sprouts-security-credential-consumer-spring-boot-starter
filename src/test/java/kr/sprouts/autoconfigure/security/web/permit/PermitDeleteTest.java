package kr.sprouts.autoconfigure.security.web.permit;

import kr.sprouts.autoconfigure.security.credential.configurations.CredentialConsumerConfiguration;
import kr.sprouts.autoconfigure.security.web.application.mock.MockPermitDeleteTestController;
import kr.sprouts.autoconfigure.security.web.configurations.SecurityWebConfiguration;
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

import java.util.logging.Logger;

@ActiveProfiles(value = "test")
@AutoConfigureMockMvc
@SpringBootTest(classes = {
        CredentialConsumerConfiguration.class,
        SecurityWebConfiguration.class,
        MockPermitDeleteTestController.class
})
class PermitDeleteTest {
    private Logger log = Logger.getLogger(PermitDeleteTest.class.getCanonicalName());
    private static final String REQUEST_URI = "/mock/permit-delete";
    private static final String BODY = "permitDelete";

    @MockBean(name = "mvcHandlerMappingIntrospector")
    private HandlerMappingIntrospector mvcHandlerMappingIntrospector;
    private final MockMvc mockMvc;

    @Autowired
    public PermitDeleteTest(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Test
    void get() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.GET, REQUEST_URI))
                .andExpect(MockMvcResultMatchers.status().isForbidden());
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
//                .andExpect(MockMvcResultMatchers.status().isOk())
//                .andExpect(MockMvcResultMatchers.content().string(BODY));
    }

    @Test
    void deleteExt() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.PATCH, REQUEST_URI + "/ext"))
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }
}
