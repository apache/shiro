/*
 * Copyright (C) 2005 Jeremy Haile
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

package org.jsecurity.web;

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.context.SecurityContext;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Description of class.
 *
 * @author Jeremy Haile
 * @since 0.1
 */
public class AuthenticationFilter implements Filter {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final String DEFAULT_UNAUTHENTICATED_PATH = "/login";
    private static final String UNAUTHENTICATED_PATH_PARAM = "unauthenticatedPath";
    private static final String UNAUTHENTICATED_SCHEME_PARAM = "unauthenticatedScheme";
    private static final String UNAUTHENTICATED_SERVERPORT_PARAM = "unauthenticatedServerPort";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private String unauthenticatedPath = DEFAULT_UNAUTHENTICATED_PATH;
    private String unauthenticatedScheme = null;
    private int unauthenticatedServerPort = -1;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    protected void setUnauthenticatedPath(String unauthenticatedPath) {
        this.unauthenticatedPath = unauthenticatedPath;
    }


    protected String getUnauthenticatedPath() {
        return unauthenticatedPath;
    }


    protected String getUnauthenticatedScheme() {
        return unauthenticatedScheme;
    }


    protected void setUnauthenticatedScheme(String unauthenticatedScheme) {
        this.unauthenticatedScheme = unauthenticatedScheme;
    }


    protected int getUnauthenticatedServerPort() {
        return unauthenticatedServerPort;
    }


    protected void setUnauthenticatedServerPort(int unauthenticatedServerPort) {
        this.unauthenticatedServerPort = unauthenticatedServerPort;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    public void init(FilterConfig filterConfig) throws ServletException {
        String unauthenticatedScheme = filterConfig.getInitParameter( UNAUTHENTICATED_SCHEME_PARAM );
        if( unauthenticatedScheme != null ) {
            setUnauthenticatedScheme( unauthenticatedScheme );
        }

        String unauthenticatedServerPort = filterConfig.getInitParameter( UNAUTHENTICATED_SERVERPORT_PARAM );
        if( unauthenticatedServerPort != null ) {
            try {
                int serverPort = Integer.parseInt( unauthenticatedServerPort );

                if( serverPort < 0 ) {
                    throw new ServletException( "The unauthenticated server port must be an integer " +
                        "greater than 0, but was [" + serverPort + "]" );
                }

                setUnauthenticatedServerPort( Integer.parseInt( unauthenticatedServerPort ) );

            } catch (NumberFormatException e) {
                throw new ServletException( "The unauthenticated server port must be a valid integer, " +
                    "but was [" + unauthenticatedServerPort + "]");
            }
        }

        String unauthenticatedUrlParam = filterConfig.getInitParameter( UNAUTHENTICATED_PATH_PARAM );
        if( unauthenticatedUrlParam != null ) {
            setUnauthenticatedPath( unauthenticatedUrlParam );
        }
    }


    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        AuthorizationContext authContext = SecurityContext.getAuthContext();

        if( authContext == null ) {
            handleUnauthenticatedRequest(request, response);
        } else {
            filterChain.doFilter( request, response );
        }

    }


    private void handleUnauthenticatedRequest(ServletRequest request, ServletResponse response) throws IOException {
        HttpServletRequest httpReq = (HttpServletRequest) request;
        HttpServletResponse httpResp = (HttpServletResponse) response;

        String scheme = getScheme(httpReq);
        String serverName = httpReq.getServerName();
        int serverPort = getServerPort(httpReq);
        String contextPath = httpReq.getContextPath();

        String redirectUrl = buildRedirectUrl(scheme, serverName, serverPort, contextPath);

        httpResp.sendRedirect( redirectUrl );
    }


    private String buildRedirectUrl(String scheme, String serverName, int serverPort, String contextPath) {

        boolean includePort = true;

        if ("http".equals(scheme.toLowerCase()) && (serverPort == 80)) {
            includePort = false;
        }

        if ("https".equals(scheme.toLowerCase()) && (serverPort == 443)) {
            includePort = false;
        }

        // Prepend a / to the beginning of the path if it was not specified
        String path = getUnauthenticatedPath();
        if( path.charAt(0) != '/' ) {
            path = "/" + path;
        }

        // Build the redirect URL
        StringBuffer sb = new StringBuffer();
        sb.append( scheme );
        sb.append( "://" );
        sb.append( serverName );
        sb.append( includePort ? ":" + serverPort : "" );
        sb.append( contextPath );
        sb.append( getUnauthenticatedPath() );

        return sb.toString();
    }


    private String getScheme(HttpServletRequest httpReq) {
        if( getUnauthenticatedScheme() != null ) {
            return getUnauthenticatedScheme();
        } else {
            return httpReq.getScheme();
        }
    }

    private int getServerPort(HttpServletRequest httpReq) {
        if( getUnauthenticatedServerPort() != -1 ) {
            return getUnauthenticatedServerPort();
        } else {
            return httpReq.getServerPort();
        }
    }


    public void destroy() {
        // Nothing to do here for this filter
    }
}