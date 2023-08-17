package kr.sprouts.autoconfigure.security.web.filer;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class PrincipalNotPresentException extends ResponseStatusException {
    public PrincipalNotPresentException() {
        super(HttpStatus.FORBIDDEN, "Principal not present.");
    }
}
