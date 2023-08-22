package kr.sprouts.autoconfigure.security.credential.components;

public class BearerTokenCredentialConsumeException extends RuntimeException {
    public BearerTokenCredentialConsumeException(Throwable cause) {
        super(cause);
    }
}
