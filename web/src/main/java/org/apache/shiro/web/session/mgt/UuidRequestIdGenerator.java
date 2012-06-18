package org.apache.shiro.web.session.mgt;

import org.apache.shiro.web.event.BeginServletRequestEvent;

import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Returns IDs based on the random {@link UUID}s.
 *
 * @see java.util.UUID#randomUUID()
 * @since 1.3
 */
public class UuidRequestIdGenerator implements RequestIdGenerator {

    private final Pattern PATTERN = Pattern.compile("-");

    public String generateId(BeginServletRequestEvent event) {
        String id = UUID.randomUUID().toString();
        return PATTERN.matcher(id).replaceAll("").toUpperCase();
    }
}
