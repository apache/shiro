/*
 * Copyright (C) 2005 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.spring.servlet.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.ri.web.WebUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Simple interceptor that verifies a user is authenticated (logged-in) before allowing a
 * page to be viewd.
 *
 * <p>If the user is not authenticated, they will be redirected to the login page located
 * at the URL {@link #getLoginURL() getLoginURL()}.  Just prior to being redirected, the
 * page URL they attempted to view is first saved in the <tt>HttpSession</tt> under the
 * key {@link WebUtils#ATTEMPTED_PAGE_KEY}.
 *
 * <p>Upon a successful login, the login controller may
 * use this session key to foward the user to the page they were attempting to view prior to
 * logging in, a nice usability feature.
 *
 * <p>The default redirect implementation is accomplished via a
 * Spring {@link RedirectView RedirectView}, {@link RedirectView#render rendered} with
 * a <tt>null</tt> model <tt>Map</tt>.  The
 * {@link #setContextRelative contextRelative}, {@link #setHttp10Compatible http10Compatible} and
 * {@link #setEncodingScheme encodingScheme} are passthrough attributes that will be set on the
 * <tt>RedirectView</tt> that is created to process the redirect.  Set them according to the
 * {@link RedirectView RedirectView} JavaDoc.
 *
 * @see RedirectView RedirectView
 *
 * @author Les Hazlewood
 */
public class AuthenticationInterceptor extends HandlerInterceptorAdapter
    implements InitializingBean {

    protected transient final Log log = LogFactory.getLog( getClass() );

    private String loginURL = null;

    private boolean contextRelative = false;

	private boolean http10Compatible = true;

	private String encodingScheme = RedirectView.DEFAULT_ENCODING_SCHEME;

    public AuthenticationInterceptor(){}

    public String getLoginURL() {
        return loginURL;
    }

    public void setLoginURL( String loginURL ) {
        this.loginURL = loginURL;
    }

    /**
	 * Set whether to interpret a given URL that starts with a slash ("/")
	 * as relative to the current ServletContext, i.e. as relative to the
	 * web application root.
	 * <p>Default is "false": A URL that starts with a slash will be interpreted
	 * as absolute, i.e. taken as-is. If true, the context path will be
	 * prepended to the URL in such a case.
	 * @see javax.servlet.http.HttpServletRequest#getContextPath
	 */
	public void setContextRelative(boolean contextRelative) {
		this.contextRelative = contextRelative;
	}

	/**
	 * Set whether a redirect will stay compatible with HTTP 1.0 clients.
	 * <p>In the default implementation, this will enforce HTTP status code 302
	 * in any case, i.e. delegate to <code>HttpServletResponse.sendRedirect</code>.
	 * Turning this off will send HTTP status code 303, which is the correct
	 * code for HTTP 1.1 clients, but not understood by HTTP 1.0 clients.
	 * <p>Many HTTP 1.1 clients treat 302 just like 303, not making any
	 * difference. However, some clients depend on 303 when redirecting
	 * after a POST request; turn this flag off in such a scenario.
	 * @see javax.servlet.http.HttpServletResponse#sendRedirect
	 */
	public void setHttp10Compatible(boolean http10Compatible) {
		this.http10Compatible = http10Compatible;
	}

	/**
	 * Set the encoding scheme for the redirect.
	 */
	public void setEncodingScheme(String encodingScheme) {
		this.encodingScheme = encodingScheme;
	}


    public void afterPropertiesSet() throws Exception {
        if ( getLoginURL() == null ) {
            String msg = "loginURL property must be set";
            throw new IllegalArgumentException( msg );
        }
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response,
                              Object handler ) throws Exception {

        AuthorizationContext authzCtx = SecurityContext.getAuthorizationContext();

        if( authzCtx == null ) {
            StringBuffer attemptedPage = request.getRequestURL();
            String queryString = request.getQueryString();
            if ( queryString != null ) {
                attemptedPage.append( "?" );
                attemptedPage.append( queryString );
            }

            HttpSession httpSession = request.getSession();
            httpSession.setAttribute( WebUtils.ATTEMPTED_PAGE_KEY, attemptedPage.toString() );

            if ( log.isDebugEnabled() ) {
                log.debug( "User is not allowed to access page [" + attemptedPage + "] without " +
                           "first being authenticated.  Redirecting to login page [" +
                           getLoginURL() + "]");
            }

            RedirectView redirect =
                new RedirectView( getLoginURL(), this.contextRelative, this.http10Compatible );
            redirect.setEncodingScheme( this.encodingScheme );
            redirect.render( null, request, response );
            return false;
        } else {
            return true;
        }
    }
}
