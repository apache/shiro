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

package org.jsecurity.ri.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.context.SecurityContext;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * Description of class.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class AuthenticationFilter implements Filter {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final String DEFAULT_UNAUTHENTICATED_PATH = "/login";
    private static final String UNAUTHENTICATED_PATH_PARAM = "unauthenticatedPath";
    private static final String UNAUTHENTICATED_SCHEME_PARAM = "unauthenticatedScheme";
    private static final String UNAUTHENTICATED_SERVERPORT_PARAM = "unauthenticatedServerPort";
    private static final String EXCLUDED_PATHS_PARAM = "excludedPaths";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected final transient Log logger = LogFactory.getLog(getClass());
    private String unauthenticatedPath = DEFAULT_UNAUTHENTICATED_PATH;
    private String unauthenticatedScheme = null;
    private int unauthenticatedServerPort = -1;
    private Set<String> excludedPaths;


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

    protected Set<String> getExcludedPaths() {
        return this.excludedPaths;
    }

    protected void addExcludedPath(String excludedPath) {

        if (logger.isDebugEnabled()) {
            logger.debug("Adding path [" + excludedPath + "] to set of excluded paths.");
        }

        this.excludedPaths.add(excludedPath);
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

        this.excludedPaths = new HashSet<String>();

        // Add the unauthenticated path to the set of excluded paths
        addExcludedPath(getUnauthenticatedPath());

        String commaSeparatedExcludedPaths = filterConfig.getInitParameter(EXCLUDED_PATHS_PARAM);
        if (commaSeparatedExcludedPaths != null) {
            String[] excludedPathArray = commaSeparatedExcludedPaths.split(",");
            for (String path : excludedPathArray) {
                addExcludedPath(path);
            }
        }
    }


    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        AuthorizationContext authContext = SecurityContext.current().getAuthorizationContext();

        String requestedPath = httpRequest.getRequestURI();

        if( authContext == null && !isPathExcluded(requestedPath)) {
            handleUnauthenticatedRequest(request, response);
        } else {
            filterChain.doFilter( request, response );
        }

    }

    private boolean isPathExcluded(String requestedPath) {
        return excludedPaths.contains(requestedPath);
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