package kr.sprouts.framework.autoconfigure.security.credential.consumer.components;

public class BearerTokenCredentialConsumeException extends RuntimeException {
    public BearerTokenCredentialConsumeException(Throwable cause) {
        super(cause);
    }
}
