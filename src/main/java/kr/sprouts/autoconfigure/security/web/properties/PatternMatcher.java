package kr.sprouts.autoconfigure.security.web.properties;

import io.jsonwebtoken.lang.Collections;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.ArrayUtils;

import java.util.List;

@Getter @Setter
public class PatternMatcher {
    List<String> patterns;

    public String[] toArray() {
        return Collections.isEmpty(patterns) ? ArrayUtils.EMPTY_STRING_ARRAY : patterns.toArray(new String[patterns.size()]);
    }
}
