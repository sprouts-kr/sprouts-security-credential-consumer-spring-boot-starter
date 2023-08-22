package kr.sprouts.autoconfigure.security.credential.consumer.components;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.sprouts.framework.library.security.credential.Credential;
import kr.sprouts.framework.library.security.credential.CredentialConsumer;
import kr.sprouts.framework.library.security.credential.CredentialConsumerSpec;
import kr.sprouts.framework.library.security.credential.Principal;
import kr.sprouts.framework.library.security.credential.cipher.Cipher;
import kr.sprouts.framework.library.security.credential.cipher.CipherAlgorithm;
import kr.sprouts.framework.library.security.credential.codec.Codec;
import kr.sprouts.framework.library.security.credential.codec.CodecType;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class ApiKeyCredentialConsumer implements CredentialConsumer<ApiKeySubject> {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UUID id;
    private final String name;
    private final Codec codec;
    private final Cipher<?> cipher;
    private final byte[] decryptSecret;
    private final List<UUID> validProviderIds;

    private ApiKeyCredentialConsumer(String consumerId, String consumerName, String codec, String algorithm, String encodedDecryptSecret, List<String> validProviderIds) {
        this.id = UUID.fromString(consumerId);
        this.name = consumerName;
        this.codec = CodecType.fromName(codec).getCodecSupplier().get();
        this.cipher = CipherAlgorithm.fromName(algorithm).getCipherSupplier().get();
        this.decryptSecret = this.codec.decode(encodedDecryptSecret);
        this.validProviderIds = validProviderIds.stream().map(UUID::fromString).collect(Collectors.toList());
    }

    public static ApiKeyCredentialConsumer of(CredentialConsumerSpec spec) {
        return new ApiKeyCredentialConsumer(
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
    public Principal<ApiKeySubject> consume(Credential credential) {
        try {
            Principal<ApiKeySubject> principal = objectMapper.readValue(cipher.decryptToString(codec.decode(credential.getValue()), decryptSecret), new TypeReference<>() {});

            if (Boolean.FALSE.equals(isValidProvider(principal.getProviderId()))) throw new InvalidCredentialProviderException();

            return principal;
        } catch (JsonProcessingException e) {
            throw new ApiKeyCredentialConsumeException(e);
        }
    }

    private Boolean isValidProvider(UUID providerId) {
        return validProviderIds.contains(providerId) ? Boolean.TRUE : Boolean.FALSE;
    }
}
