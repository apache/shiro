package org.apache.shiro.web.event;

import org.apache.shiro.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Event triggered at the beginning of a Shiro-filtered servlet request, before the filter chain has been invoked.
 *
 * @since 1.3
 */
public class BeginServletRequestEvent extends ServletRequestEvent {

    public BeginServletRequestEvent(Subject subject, ServletRequest servletRequest, ServletResponse servletResponse) {
        super(subject, servletRequest, servletResponse);
    }
}
