package kr.sprouts.autoconfigure.security.web.configurations;

import kr.sprouts.autoconfigure.security.credential.components.CredentialConsumerManager;
import kr.sprouts.autoconfigure.security.credential.configurations.CredentialConsumerConfiguration;
import kr.sprouts.autoconfigure.security.credential.properties.CredentialConsumerConfigurationProperty;
import kr.sprouts.autoconfigure.security.web.components.CredentialConsumeFilter;
import kr.sprouts.autoconfigure.security.web.properties.PatternMatcher;
import kr.sprouts.autoconfigure.security.web.properties.SecurityHttpPermitProperty;
import kr.sprouts.autoconfigure.security.web.properties.SecurityWebIgnoreProperty;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsUtils;

import java.util.Optional;

@AutoConfigureAfter(value = {
        CredentialConsumerConfiguration.class
})
@Configuration
@EnableConfigurationProperties(value = {
        SecurityHttpPermitProperty.class,
        SecurityWebIgnoreProperty.class
})
@Slf4j
@Getter
public class SecurityWebConfiguration {
    private final CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty;
    private final CredentialConsumerManager credentialConsumerManager;
    private final SecurityHttpPermitProperty securityHttpPermitProperty;
    private final SecurityWebIgnoreProperty securityWebIgnoreProperty;

    public SecurityWebConfiguration(CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty, CredentialConsumerManager credentialConsumerManager, SecurityHttpPermitProperty securityHttpPermitProperty, SecurityWebIgnoreProperty securityWebIgnoreProperty) {
        this.credentialConsumerConfigurationProperty = credentialConsumerConfigurationProperty;
        this.credentialConsumerManager = credentialConsumerManager;
        this.securityHttpPermitProperty = securityHttpPermitProperty;
        this.securityWebIgnoreProperty = securityWebIgnoreProperty;

        if (log.isInfoEnabled()) log.info("Initialized SecurityConfiguration");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        if (credentialConsumerConfigurationProperty == null) throw new InitializeSecurityFilterChainException();
        if (securityHttpPermitProperty == null) throw new InitializeSecurityFilterChainException();

        httpSecurity
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .headers(httpSecurityHeadersConfigurer -> httpSecurityHeadersConfigurer.frameOptions().sameOrigin())
                .sessionManagement(filter -> filter.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        Optional<PatternMatcher> permitAll = Optional.ofNullable(securityHttpPermitProperty.getPermitAll());
        Optional<PatternMatcher> permitGet = Optional.ofNullable(securityHttpPermitProperty.getPermitGet());
        Optional<PatternMatcher> permitPost = Optional.ofNullable(securityHttpPermitProperty.getPermitPost());
        Optional<PatternMatcher> permitPut = Optional.ofNullable(securityHttpPermitProperty.getPermitPut());
        Optional<PatternMatcher> permitPatch = Optional.ofNullable(securityHttpPermitProperty.getPermitPatch());
        Optional<PatternMatcher> permitDelete = Optional.ofNullable(securityHttpPermitProperty.getPermitDelete());

        httpSecurity
                .addFilterBefore(new CredentialConsumeFilter(credentialConsumerConfigurationProperty, credentialConsumerManager), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests(customizer -> {
                    permitAll.ifPresent(patternMatcher -> customizer.antMatchers(patternMatcher.toArray()).permitAll());
                    permitGet.ifPresent(patternMatcher -> customizer.antMatchers(HttpMethod.GET, patternMatcher.toArray()).permitAll());
                    permitPost.ifPresent(patternMatcher -> customizer.antMatchers(HttpMethod.POST, patternMatcher.toArray()).permitAll());
                    permitPut.ifPresent(patternMatcher -> customizer.antMatchers(HttpMethod.PUT, patternMatcher.toArray()).permitAll());
                    permitPatch.ifPresent(patternMatcher -> customizer.antMatchers(HttpMethod.PATCH, patternMatcher.toArray()).permitAll());
                    permitDelete.ifPresent(patternMatcher -> customizer.antMatchers(HttpMethod.DELETE, patternMatcher.toArray()).permitAll());

                    customizer.requestMatchers(CorsUtils::isPreFlightRequest).permitAll();
                    customizer.anyRequest().authenticated();
                });

        if (log.isInfoEnabled()) log.info("Created bean SecurityFilterChain");

        return httpSecurity.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        if (securityWebIgnoreProperty == null) throw new InitializeWebSecurityCustomizerException();

        Optional<PatternMatcher> ignore = Optional.ofNullable(securityWebIgnoreProperty.getIgnore());

        WebSecurityCustomizer webSecurityCustomizer =
                (customizer -> ignore.ifPresent(patternMatcher -> customizer.ignoring().antMatchers(patternMatcher.toArray())));

        if (log.isInfoEnabled()) log.info("Created bean WebSecurityCustomizer");

        return webSecurityCustomizer;
    }
}
