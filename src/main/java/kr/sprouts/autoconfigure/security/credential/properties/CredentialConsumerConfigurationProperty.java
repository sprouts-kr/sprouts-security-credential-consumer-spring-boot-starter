package kr.sprouts.autoconfigure.security.credential.properties;

import kr.sprouts.security.credential.CredentialConsumerSpec;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "sprouts.security.credential")
@Getter @Setter
public class CredentialConsumerConfigurationProperty {
    private List<CredentialConsumerSpec> consumers;
}
