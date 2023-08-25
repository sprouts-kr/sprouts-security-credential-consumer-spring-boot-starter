package kr.sprouts.framework.autoconfigure.security.web.components;

import kr.sprouts.framework.autoconfigure.security.credential.consumer.components.CredentialConsumerManager;
import kr.sprouts.framework.autoconfigure.security.credential.consumer.properties.CredentialConsumerConfigurationProperty;
import kr.sprouts.framework.library.security.credential.Credential;
import kr.sprouts.framework.library.security.credential.CredentialConsumer;
import kr.sprouts.framework.library.security.credential.CredentialHeaderSpec;
import kr.sprouts.framework.library.security.credential.Principal;
import kr.sprouts.framework.library.security.credential.codec.Codec;
import kr.sprouts.framework.library.security.credential.codec.CodecType;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.SerializationUtils;
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
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class CredentialConsumeFilter extends OncePerRequestFilter {
    private final CredentialHeaderSpec credentialHeaderSpec;
    private final CredentialConsumerManager credentialConsumerManager;
    private final Codec codec;

    public CredentialConsumeFilter(CredentialConsumerConfigurationProperty credentialConsumerConfigurationProperty, CredentialConsumerManager credentialConsumerManager) {
        this.credentialConsumerManager = credentialConsumerManager;
        this.credentialHeaderSpec = credentialConsumerConfigurationProperty.getHeader();

        if (this.credentialConsumerManager == null || this.credentialHeaderSpec == null) {
            throw new InitializeCredentialConsumeFilterException();
        }

        this.codec = CodecType.fromName(this.credentialHeaderSpec.getCodec()).getCodecSupplier().get();

        if (this.codec == null) {
            throw new InitializeCredentialConsumeFilterException();
        }

        if (log.isInfoEnabled()) log.info("Created filter CredentialConsumeFilter");
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
            String authorizationHeaderName = credentialHeaderSpec.getName();
            String authorizationPrefix = credentialHeaderSpec.getPrefix();

            if (StringUtils.isEmpty(authorizationHeaderName) || StringUtils.isEmpty(authorizationPrefix)) {
                return ConsumeResult.failed();
            }

            String authorizationValue = request.getHeader(authorizationHeaderName);

            if (StringUtils.isEmpty(authorizationValue)
                    || Boolean.FALSE.equals(authorizationValue.startsWith(authorizationPrefix))
                    || authorizationValue.trim().length() <= authorizationPrefix.length() ) {
                return ConsumeResult.failed();
            }

            Object credentialObject = SerializationUtils.deserialize(
                    codec.decode(authorizationValue.substring(authorizationPrefix.length()).trim())
            );

            if (Boolean.FALSE.equals(credentialObject instanceof Credential)) {
                return ConsumeResult.failed();
            }

            Credential credential = (Credential) credentialObject;

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
