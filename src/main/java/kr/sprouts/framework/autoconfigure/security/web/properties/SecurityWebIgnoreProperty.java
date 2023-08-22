package kr.sprouts.framework.autoconfigure.security.web.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sprouts.security.web")
@Getter @Setter
public class SecurityWebIgnoreProperty {
    private PatternMatcher ignore;
}
