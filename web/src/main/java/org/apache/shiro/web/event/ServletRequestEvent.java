package org.apache.shiro.web.event;

import org.apache.shiro.event.SubjectEvent;
import org.apache.shiro.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * An event triggered during the lifecycle of a Shiro-filtered ServletRequest.
 *
 * @since 1.3
 */
public class ServletRequestEvent extends SubjectEvent {

    private final ServletRequest servletRequest;
    private final ServletResponse servletResponse;

    public ServletRequestEvent(Subject subject, ServletRequest servletRequest, ServletResponse servletResponse) {
        super(subject);
        this.servletRequest = servletRequest;
        this.servletResponse = servletResponse;
    }

    public ServletRequest getServletRequest() {
        return servletRequest;
    }

    public ServletResponse getServletResponse() {
        return servletResponse;
    }
}
