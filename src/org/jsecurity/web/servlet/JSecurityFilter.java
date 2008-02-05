package org.jsecurity.web.servlet;

import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.support.SecurityWebSupport;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Les Hazlewood
 * @since Feb 4, 2008 7:38:44 PM
 */
public class JSecurityFilter extends SecurityManagerFilter {

    protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        ThreadContext.bind( SecurityWebSupport.getInetAddress( request ) );

        boolean httpSessions = isHttpSessions();
        request = new JSecurityHttpServletRequest( request, getServletContext(), httpSessions );
        if ( !httpSessions ) {
            //the JSecurityHttpServletResponse exists to support URL rewriting for session ids.  This is only needed if
            //using JSecurity sessions (i.e. not simple HttpSession based sessions):
            response = new JSecurityHttpServletResponse( response, getServletContext(), (JSecurityHttpServletRequest)request );
        }

        ThreadContext.bind( request );
        ThreadContext.bind( response );

        try {
            chain.doFilter( request, response );
        } finally {
            ThreadContext.unbindServletRequest();
            ThreadContext.unbindServletResponse();
            ThreadContext.unbindInetAddress();
        }
    }
}
