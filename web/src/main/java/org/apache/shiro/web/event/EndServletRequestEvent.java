package org.apache.shiro.web.event;

import org.apache.shiro.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Event triggered at the end of a Shiro-filtered servlet request.
 *
 * @since 1.3
 */
public class EndServletRequestEvent extends ServletRequestEvent {

    private final Throwable throwable;

    public EndServletRequestEvent(Subject subject, ServletRequest servletRequest, ServletResponse servletResponse, Throwable t) {
        super(subject, servletRequest, servletResponse);
        this.throwable = t;
    }

    /**
     * Returns any Throwable that might have resulted during request execution or {@code null} if no Throwable was
     * triggered.
     *
     * @return any Throwable that might have resulted during request execution or {@code null} if no Throwable was
     *         triggered.
     */
    public Throwable getThrowable() {
        return throwable;
    }
}
