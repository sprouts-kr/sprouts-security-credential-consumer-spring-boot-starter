package kr.sprouts.autoconfigure.security.credential.properties;

import kr.sprouts.framework.library.security.credential.CredentialConsumerSpec;
import kr.sprouts.framework.library.security.credential.CredentialHeaderSpec;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "sprouts.security.credential")
@Getter @Setter
public class CredentialConsumerConfigurationProperty {
    private CredentialHeaderSpec header;
    private List<CredentialConsumerSpec> consumers;
}
