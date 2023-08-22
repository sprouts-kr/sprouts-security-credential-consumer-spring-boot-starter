package kr.sprouts.autoconfigure.security.web.components;

import kr.sprouts.autoconfigure.security.credential.consumers.CredentialConsumerManager;
import kr.sprouts.autoconfigure.security.credential.properties.CredentialConsumerConfigurationProperty;
import kr.sprouts.framework.library.security.credential.Credential;
import kr.sprouts.framework.library.security.credential.CredentialConsumer;
import kr.sprouts.framework.library.security.credential.CredentialHeaderSpec;
import kr.sprouts.framework.library.security.credential.Principal;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class CredentialConsumeFilter extends OncePerRequestFilter {
    private final Logger log = Logger.getLogger(CredentialConsumeFilter.class.getCanonicalName());
    private final CredentialHeaderSpec credentialHeaderSpec;
    private final CredentialConsumerManager credentialConsumerManager;
    private static final String SEPARATOR_CHARS = ",";

    public CredentialConsumeFilter(CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty, CredentialConsumerManager credentialConsumerManager) {
        this.credentialConsumerManager = credentialConsumerManager;
        this.credentialHeaderSpec = credentialConsumerConfigurationProperty.getHeader();

        if (this.credentialConsumerManager == null || this.credentialHeaderSpec == null) {
            throw new InitializeCredentialConsumeFilterException();
        }

        if (log.isLoggable(Level.INFO)) log.info("Created filter CredentialConsumeFilter");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        ConsumeResult result =  consumeRequest(request);

        if (Boolean.TRUE.equals(result.isSucceeded())) {
            SecurityContextHolder.getContext().setAuthentication(generateAuthentication(result));
        }

        filterChain.doFilter(request, response);
    }

    private Authentication generateAuthentication(ConsumeResult result) {
        UUID memberId = result.getPrincipal().orElseThrow(PrincipalNotPresentException::new).getSubject().getMemberId();

        return new UsernamePasswordAuthenticationToken(
                new User(memberId.toString(), StringUtils.EMPTY, new ArrayList<>()),
                result.getCredential(),
                new ArrayList<>()
        );
    }

    private ConsumeResult consumeRequest(HttpServletRequest request) {
        try {
            String providerHeaderName = credentialHeaderSpec.getProviderHeaderName();
            String consumerHeaderName = credentialHeaderSpec.getConsumerHeaderName();
            String valueHeaderName = credentialHeaderSpec.getValueHeaderName();

            if (StringUtils.isEmpty(providerHeaderName) || StringUtils.isEmpty(consumerHeaderName) || StringUtils.isEmpty(valueHeaderName)) {
                return ConsumeResult.failed();
            }

            String providerHeader = request.getHeader(providerHeaderName);
            String consumerHeader = request.getHeader(consumerHeaderName);
            String valueHeader = request.getHeader(valueHeaderName);

            if (StringUtils.isEmpty(providerHeader) || StringUtils.isEmpty(consumerHeader) || StringUtils.isEmpty(valueHeader)) {
                return ConsumeResult.failed();
            }

            UUID providerId = UUID.fromString(request.getHeader(providerHeaderName));
            List<UUID> consumerIds = Arrays.stream(StringUtils.split(request.getHeader(consumerHeaderName), SEPARATOR_CHARS))
                    .map(consumerIdString -> UUID.fromString(StringUtils.trim(consumerIdString)))
                    .collect(Collectors.toList());
            String value = request.getHeader(valueHeaderName);

            Credential credential = Credential.of(providerId, consumerIds, value);

            AtomicReference<CredentialConsumer<?>> consumer = new AtomicReference<>();

            for (UUID targetConsumer: credential.getConsumerIds()) {
                credentialConsumerManager.get(targetConsumer).ifPresent(consumer::set);

                if (consumer.get() != null) break;
            }

            if (consumer.get() == null) {
                return ConsumeResult.failed(credential);
            }

            return ConsumeResult.succeeded(consumer.get().consume(credential), credential);
        } catch (RuntimeException e) {
            return ConsumeResult.failed();
        }
    }

    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    private static class ConsumeResult {
        private final Boolean succeeded;
        private final Principal<?> principal;
        @Getter
        private final Credential credential;

        public static ConsumeResult succeeded(Principal<?> principal, Credential credential) {
            return new ConsumeResult(Boolean.TRUE, principal, credential);
        }

        public static ConsumeResult failed() {
            return new ConsumeResult(Boolean.FALSE, null, null);
        }

        public static ConsumeResult failed(Credential credential) {
            return new ConsumeResult(Boolean.FALSE, null, credential);
        }

        public Boolean isSucceeded() {
            return succeeded;
        }

        public Optional<Principal<?>> getPrincipal() {
            return Optional.of(principal);
        }
    }
}
