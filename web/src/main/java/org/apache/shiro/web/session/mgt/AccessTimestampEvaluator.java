package org.apache.shiro.web.session.mgt;

import org.apache.shiro.web.event.BeginServletRequestEvent;

/**
 * Component that allows customization of when a valid session's lastAccessTimestamp will be updated.
 * <p/>
 * The Servlet Specification specifies that a session lastAccessTimestamp will be updated on each request that is
 * associated with a valid session.  Default implementations of this interface enforce this (expected) behavior.
 * <p/>
 * <b>WARNING:</b> Be careful about changing the default behavior of these implementations or writing your own.
 * If sessions' last access timestamps are not updated properly, they will not time out as expected, which could
 * introduce security attack vectors.
 * <p/>
 * However, scrutinized implementations of this interface can be useful in certain scenarios, depending on business
 * and/or security requirements.
 *
 * @see <a href="http://www.scribd.com/doc/23278127/58/SRV-7-6-Last-Accessed-Times">Servlet Specification, Section 7.6</a>
 * @since 1.3
 */
public interface AccessTimestampEvaluator {

    /**
     * Returns {@code true} if a request with an associated valid session should result in updating the session's
     * {@code lastAccessTimestamp} to the current time this method is invoked, {@code false} otherwise.
     * <p/>
     * <b>Servlet Specification-compliant implementations always return {@code true}</b> to guarantee default
     * session behavior.  However, returning false may be useful in certain scenarios depending on business and/or
     * security requirements.  If you implement this interface, return {@code false} judiciously.
     * <p/>
     * See the class-level JavaDoc for more.
     *
     * @param event the event that indicates a request is starting (but not yet propagated down the servlet filter
     *              chain).
     * @return {@code true} if a request with an associated valid session should result in updating the session's
     *         {@code lastAccessTimestamp} to the current time this method is invoked, {@code false} otherwise.
     */
    boolean isUpdateAccessTimestamp(BeginServletRequestEvent event);
}
