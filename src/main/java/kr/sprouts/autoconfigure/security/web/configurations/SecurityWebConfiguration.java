package kr.sprouts.autoconfigure.security.web.configurations;

import kr.sprouts.autoconfigure.security.credential.configurations.CredentialConsumerConfiguration;
import kr.sprouts.autoconfigure.security.credential.consumers.CredentialConsumerManager;
import kr.sprouts.autoconfigure.security.credential.properties.CredentialConsumerConfigurationProperty;
import kr.sprouts.autoconfigure.security.web.filer.CredentialConsumeFilter;
import kr.sprouts.autoconfigure.security.web.properties.SecurityHttpPermitProperty;
import kr.sprouts.autoconfigure.security.web.properties.SecurityWebIgnoreProperty;
import lombok.Getter;
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
import java.util.logging.Level;
import java.util.logging.Logger;

@AutoConfigureAfter(value = {
        CredentialConsumerConfiguration.class
})
@Configuration
@EnableConfigurationProperties(value = {
        SecurityHttpPermitProperty.class,
        SecurityWebIgnoreProperty.class
})
public class SecurityWebConfiguration {
    private final Logger log = Logger.getLogger(SecurityWebConfiguration.class.getCanonicalName());

    @Getter
    private final CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty;
    @Getter
    private final CredentialConsumerManager credentialConsumerManager;
    @Getter
    private final SecurityHttpPermitProperty securityHttpPermitProperty;
    @Getter
    private final SecurityWebIgnoreProperty securityWebIgnoreProperty;

    public SecurityWebConfiguration(CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty, CredentialConsumerManager credentialConsumerManager, SecurityHttpPermitProperty securityHttpPermitProperty, SecurityWebIgnoreProperty securityWebIgnoreProperty) {
        this.credentialConsumerConfigurationProperty = credentialConsumerConfigurationProperty;
        this.credentialConsumerManager = credentialConsumerManager;
        this.securityHttpPermitProperty = securityHttpPermitProperty;
        this.securityWebIgnoreProperty = securityWebIgnoreProperty;

        if (log.isLoggable(Level.INFO)) log.info("Initialized SecurityConfiguration");
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

        Optional<String[]> permitAllPatterns = Optional.of(securityHttpPermitProperty.getPermitAll().toArray());
        Optional<String[]> permitGetPatterns = Optional.of(securityHttpPermitProperty.getPermitGet().toArray());
        Optional<String[]> permitPostPatterns = Optional.of(securityHttpPermitProperty.getPermitPost().toArray());
        Optional<String[]> permitPutPatterns = Optional.of(securityHttpPermitProperty.getPermitPut().toArray());
        Optional<String[]> permitPatchPatterns = Optional.of(securityHttpPermitProperty.getPermitPatch().toArray());
        Optional<String[]> permitDeletePatterns = Optional.of(securityHttpPermitProperty.getPermitDelete().toArray());

        httpSecurity
                .addFilterBefore(new CredentialConsumeFilter(credentialConsumerConfigurationProperty, credentialConsumerManager), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests(customizer -> {

                    permitAllPatterns.ifPresent(patterns -> customizer.antMatchers(patterns).permitAll());
                    permitGetPatterns.ifPresent(patterns -> customizer.antMatchers(HttpMethod.GET, patterns).permitAll());
                    permitPostPatterns.ifPresent(patterns -> customizer.antMatchers(HttpMethod.POST, patterns).permitAll());
                    permitPutPatterns.ifPresent(patterns -> customizer.antMatchers(HttpMethod.PUT, patterns).permitAll());
                    permitPatchPatterns.ifPresent(patterns -> customizer.antMatchers(HttpMethod.PATCH, patterns).permitAll());
                    permitDeletePatterns.ifPresent(patterns -> customizer.antMatchers(HttpMethod.DELETE, patterns).permitAll());

                    customizer.requestMatchers(CorsUtils::isPreFlightRequest).permitAll();
                    customizer.anyRequest().authenticated();
                });

        if (log.isLoggable(Level.INFO)) log.info("Created bean SecurityFilterChain");

        return httpSecurity.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        if (securityWebIgnoreProperty == null) throw new InitializeWebSecurityCustomizerException();

        WebSecurityCustomizer webSecurityCustomizer = (customizer -> {
            if (securityWebIgnoreProperty.getIgnore() != null) {
                customizer.ignoring().antMatchers(
                        securityWebIgnoreProperty.getIgnore().toArray()
                );
            }
        });

        if (log.isLoggable(Level.INFO)) log.info("Created bean WebSecurityCustomizer");

        return webSecurityCustomizer;
    }
}
