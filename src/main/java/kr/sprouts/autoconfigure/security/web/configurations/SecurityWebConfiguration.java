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
                .sessionManagement(filter -> filter.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new CredentialConsumeFilter(credentialConsumerConfigurationProperty, credentialConsumerManager), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests(customizer -> {
                    if (securityHttpPermitProperty.getPermitAll() != null
                            && securityHttpPermitProperty.getPermitAll().getPatterns() != null) {
                        customizer.antMatchers(
                                securityHttpPermitProperty.getPermitAll().toArray()
                        ).permitAll();
                    }
                    if (securityHttpPermitProperty.getPermitGet() != null
                            && securityHttpPermitProperty.getPermitGet().getPatterns() != null) {
                        customizer.antMatchers(
                                HttpMethod.GET,
                                securityHttpPermitProperty.getPermitGet().toArray()
                        ).permitAll();
                    }
                    if (securityHttpPermitProperty.getPermitPost() != null
                            && securityHttpPermitProperty.getPermitPost().getPatterns() != null) {
                        customizer.antMatchers(
                                HttpMethod.POST,
                                securityHttpPermitProperty.getPermitPost().toArray()
                        ).permitAll();
                    }
                    if (securityHttpPermitProperty.getPermitPut() != null
                            && securityHttpPermitProperty.getPermitPut().getPatterns() != null) {
                        customizer.antMatchers(
                                HttpMethod.PUT,
                                securityHttpPermitProperty.getPermitPut().toArray()
                        ).permitAll();
                    }
                    if (securityHttpPermitProperty.getPermitPatch() != null
                            && securityHttpPermitProperty.getPermitPatch().getPatterns() != null) {
                        customizer.antMatchers(
                                HttpMethod.PATCH,
                                securityHttpPermitProperty.getPermitPatch().toArray()
                        ).permitAll();
                    }
                    if (securityHttpPermitProperty.getPermitDelete() != null
                            && securityHttpPermitProperty.getPermitDelete().getPatterns() != null) {
                        customizer.antMatchers(
                                HttpMethod.DELETE,
                                securityHttpPermitProperty.getPermitDelete().toArray()
                        ).permitAll();
                    }
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
