package kr.sprouts.autoconfigure.security.credential.consumers;

public class BearerTokenCredentialConsumeException extends RuntimeException {
    public BearerTokenCredentialConsumeException(Throwable cause) {
        super(cause);
    }
}
