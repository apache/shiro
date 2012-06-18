package org.apache.shiro.web.session.mgt;

import org.apache.shiro.web.event.BeginServletRequestEvent;

/**
 * Servlet Specification-compliant implementation that always returns {@code true}.
 *
 * @since 1.3
 */
public class SpecCompliantAccessTimestampEvaluator implements AccessTimestampEvaluator {

    /**
     * Servlet Specification-compliant implementation that always returns {@code true}.
     */
    public boolean isUpdateAccessTimestamp(BeginServletRequestEvent event) {
        return true;
    }
}
