package kr.sprouts.autoconfigure.security.credential.consumers;

public class ApiKeyCredentialConsumeException extends RuntimeException {
    public ApiKeyCredentialConsumeException(Throwable cause) {
        super(cause);
    }
}
