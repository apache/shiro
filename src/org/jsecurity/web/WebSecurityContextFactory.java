package org.jsecurity.web;

import org.jsecurity.context.SecurityContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public interface WebSecurityContextFactory {

    SecurityContext createSecurityContext( ServletRequest servletRequest, ServletResponse servletResponse );
}
