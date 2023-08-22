package kr.sprouts.autoconfigure.security.credential.consumer.components;

import kr.sprouts.framework.library.security.credential.Subject;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.UUID;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public class BearerTokenSubject extends Subject {
    private Long validityInMinutes;

    private BearerTokenSubject(UUID memberId, Long validityInMinute) {
        super(memberId);
        this.validityInMinutes = validityInMinute;
    }

    public static BearerTokenSubject of(UUID memberId, Long validityInMinutes) {
        return new BearerTokenSubject(memberId, validityInMinutes);
    }
}
