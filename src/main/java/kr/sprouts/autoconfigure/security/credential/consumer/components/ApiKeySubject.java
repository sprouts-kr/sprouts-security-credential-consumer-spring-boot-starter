package kr.sprouts.autoconfigure.security.credential.consumer.components;

import kr.sprouts.framework.library.security.credential.Subject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.UUID;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ApiKeySubject extends Subject {
    private ApiKeySubject(UUID memberId) {
        super(memberId);
    }

    public static ApiKeySubject of(UUID memberId) {
        return new ApiKeySubject(memberId);
    }
}
