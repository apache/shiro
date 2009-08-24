package org.apache.shiro.web.subject;

import org.apache.shiro.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * A {@code WebSubject} represents a Subject instance that was acquired upon receiving a {@link ServletRequest}.
 *
 * @since 1.0
 */
public interface WebSubject extends Subject {

    /**
     * Returns the {@code ServletRequest} accessible when the Subject instance was created.
     *
     * @return the {@code ServletRequest} accessible when the Subject instance was created.
     */
    ServletRequest getServletRequest();

    /**
     * Returns the {@code ServletResponse} accessible when the Subject instance was created.
     *
     * @return the {@code ServletResponse} accessible when the Subject instance was created.
     */
    ServletResponse getServletResponse();

}
