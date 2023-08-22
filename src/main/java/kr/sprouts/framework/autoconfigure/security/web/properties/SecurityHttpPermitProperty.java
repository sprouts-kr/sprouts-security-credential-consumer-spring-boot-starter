package kr.sprouts.framework.autoconfigure.security.web.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sprouts.security.http")
@Getter @Setter
public class SecurityHttpPermitProperty {
    private PatternMatcher permitAll;
    private PatternMatcher permitGet;
    private PatternMatcher permitPost;
    private PatternMatcher permitPut;
    private PatternMatcher permitPatch;
    private PatternMatcher permitDelete;
}
