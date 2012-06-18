package org.apache.shiro.web.session.mgt;

import org.apache.shiro.web.event.BeginServletRequestEvent;

/**
 * Generates globally unique IDs to assign to ServletRequests (for example, as a request attribute).  This is
 * useful for debugging in multi-threaded/multi-request environments.
 *
 * @since 1.3
 */
public interface RequestIdGenerator {

    /**
     * Returns a globally unique request ID to be associated with an incoming ServletRequest, or {@code null} if no
     * ID should be associated.  Useful for debugging in multi-threaded/multi-request environments.
     *
     * @return a globally unique request ID to be associated with an incoming ServletRequest, or {@code null} if no
     *         ID should be associated.
     */
    String generateId(BeginServletRequestEvent event);
}
