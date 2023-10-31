package kr.sprouts.framework.autoconfigure.security.credential.consumer.components;

import io.jsonwebtoken.Claims;
import kr.sprouts.framework.library.security.credential.Credential;
import kr.sprouts.framework.library.security.credential.CredentialConsumer;
import kr.sprouts.framework.library.security.credential.CredentialConsumerSpec;
import kr.sprouts.framework.library.security.credential.Principal;
import kr.sprouts.framework.library.security.credential.codec.Codec;
import kr.sprouts.framework.library.security.credential.codec.CodecType;
import kr.sprouts.framework.library.security.credential.jwt.Jwt;
import kr.sprouts.framework.library.security.credential.jwt.JwtAlgorithm;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class BearerTokenCredentialConsumer implements CredentialConsumer<BearerTokenSubject> {
    private final UUID id;
    private final String name;
    private final Codec codec;
    private final Jwt<?> jwt;
    private final byte[] decryptSecret;
    private final List<UUID> validProviderIds;

    private BearerTokenCredentialConsumer(String consumerId, String consumerName, String codec, String algorithm, String encodedDecryptSecret, List<String> validProviderIds) {
        this.id = UUID.fromString(consumerId);
        this.name = consumerName;
        this.codec = CodecType.fromName(codec).getCodecSupplier().get();
        this.jwt = JwtAlgorithm.fromName(algorithm).getJwtSupplier().get();
        this.decryptSecret = this.codec.decode(encodedDecryptSecret);
        this.validProviderIds = validProviderIds.stream().map(UUID::fromString).collect(Collectors.toList());
    }

    public static BearerTokenCredentialConsumer of(CredentialConsumerSpec spec) {
        return new BearerTokenCredentialConsumer(
                spec.getId(),
                spec.getName(),
                spec.getCodec(),
                spec.getAlgorithm(),
                spec.getEncodedSecret(),
                spec.getValidProviders().stream().map(CredentialConsumerSpec.ValidProvider::getId).collect(Collectors.toList())
        );
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Principal<BearerTokenSubject> consume(Credential credential) {
        Principal<BearerTokenSubject> principal = principal(jwt.parseClaimsJws(credential.getValue(), decryptSecret));

        if (Boolean.FALSE.equals(isValidProvider(principal.getProviderId()))) throw new InvalidCredentialProviderException();

        return principal;
    }

    private Principal<BearerTokenSubject> principal(Claims claims) {
        return Principal.of(
                UUID.fromString(claims.getIssuer()),
                claims.getAudience().stream().map(UUID::fromString).collect(Collectors.toList()),
                BearerTokenSubject.of(
                        UUID.fromString(claims.getSubject()),
                        TimeUnit.MINUTES.convert(Math.abs(claims.getExpiration().getTime() - claims.getIssuedAt().getTime()), TimeUnit.MILLISECONDS)
                )
        );
    }

    private Boolean isValidProvider(UUID providerId) {
        return validProviderIds.contains(providerId) ? Boolean.TRUE : Boolean.FALSE;
    }
}
