/*
* Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.web.support;

import org.jsecurity.SecurityUtils;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.*;

/**
 * TODO - class JavaDoc
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class AuthenticationWebInterceptor extends SecurityWebInterceptor {

    /**
     * Default encoding scheme used if none is specified (value of UTF-8).
     */
    public static final String DEFAULT_ENCODING_SCHEME = "UTF-8";

    public static final String DEFAULT_ATTEMPTED_PAGE_KEY =
        AuthenticationWebInterceptor.class.getName() + "_ATTEMPTED_PAGE_KEY";

    /**
     * Because urls can have commas and semicolons, the default delimiters for excludedPaths are whitespace chars
     * (space, newline, carriage return, and tab).
     */
    public static final String DEFAULT_DELIMITERS = " \n\r\t";

    private String redirectUrl = null;

    private boolean contextRelative = false;
    private boolean http10Compatible = true;
    private String encodingScheme = RedirectView.DEFAULT_ENCODING_SCHEME;

    private AttemptedPageStorageScheme attemptedPageStorageScheme = AttemptedPageStorageScheme.requestParameter;
    private String attemptedPageKeyName = DEFAULT_ATTEMPTED_PAGE_KEY;

    private Set<String> excludedPaths = new HashSet<String>();
    private String excludedPathsDelimiters = " \n\r\t";

    public AuthenticationWebInterceptor() {
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl( String redirectUrl ) {
        this.redirectUrl = redirectUrl;
    }

    /**
     * Set whether to interpret a given URL that starts with a slash ("/")
     * as relative to the current ServletContext, i.e. as relative to the
     * web application root.
     * <p>Default is "false": A URL that starts with a slash will be interpreted
     * as absolute, i.e. taken as-is. If true, the context path will be
     * prepended to the URL in such a case.
     *
     * @param contextRelative whether or not to interpret a redirect url as relateive to the current ServletContext, default is false.
     * @see javax.servlet.http.HttpServletRequest#getContextPath
     */
    public void setContextRelative( boolean contextRelative ) {
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
     *
     * @param http10Compatible whether a redirect will stay compatible with HTTP 1.0 clients, default is true
     * @see javax.servlet.http.HttpServletResponse#sendRedirect
     */
    public void setHttp10Compatible( boolean http10Compatible ) {
        this.http10Compatible = http10Compatible;
    }

    /**
     * Set the encoding scheme for the redirect.
     *
     * @param encodingScheme the encoding scheme for the redirect, default is {@link #DEFAULT_ENCODING_SCHEME};
     */
    public void setEncodingScheme( String encodingScheme ) {
        this.encodingScheme = encodingScheme;
    }


    public AttemptedPageStorageScheme getAttemptedPageStorageScheme() {
        return attemptedPageStorageScheme;
    }

    public void setAttemptedPageStorageScheme( AttemptedPageStorageScheme attemptedPageStorageScheme ) {
        this.attemptedPageStorageScheme = attemptedPageStorageScheme;
    }

    public String getAttemptedPageKeyName() {
        return attemptedPageKeyName;
    }

    public void setAttemptedPageKeyName( String attemptedPageKeyName ) {
        this.attemptedPageKeyName = attemptedPageKeyName;
    }

    public String getExcludedPathsDelimiters() {
        return excludedPathsDelimiters;
    }

    public void setExcludedPathsDelimiters( String excludedPathsDelimiters ) {
        this.excludedPathsDelimiters = excludedPathsDelimiters;
    }

    protected Set<String> getExcludedPaths() {
        return this.excludedPaths;
    }

    public void setExcludedPaths( Set<String> excludedPaths ) {
        this.excludedPaths = excludedPaths;
    }

    public void setExcludedPaths( String delimitedPaths ) {
        if ( delimitedPaths == null || delimitedPaths.trim().length() == 0 ) {
            throw new IllegalArgumentException( "delimitedPaths argument cannot be null or empty." );
        }
        String delimiters = getExcludedPathsDelimiters();
        if ( delimiters == null ) {
            delimiters = DEFAULT_DELIMITERS;
        }
        StringTokenizer st = new StringTokenizer( delimitedPaths, delimiters );
        while ( st.hasMoreTokens() ) {
            String token = st.nextToken();
            token = token.trim();
            if ( token.length() > 0 ) {
                addExcludedPath( token );
            }
        }
    }

    protected void addExcludedPath( String excludedPath ) {
        if ( excludedPath == null || excludedPath.trim().length() == 0 ) {
            throw new IllegalArgumentException( "excludedPath argument cannot be null or empty" );
        }
        if ( log.isDebugEnabled() ) {
            log.debug( "Adding path [" + excludedPath + "] to set of excluded paths." );
        }
        this.excludedPaths.add( excludedPath );
    }

    public void init() throws Exception {
        if ( getRedirectUrl() == null ) {
            String msg = "redirectUrl property must be set";
            throw new IllegalArgumentException( msg );
        }
        if ( attemptedPageStorageScheme == null ) {
            if ( log.isInfoEnabled() ) {
                log.info( "No 'attemptedPageStorageScheme' attribute set - the user's attempted page will not " +
                    "be available after the redirect to the login page." );
            }
        }
    }

    protected SecurityContext getSecurityContext( HttpServletRequest request, HttpServletResponse response ) {
        return SecurityUtils.getSecurityContext();
    }

    protected RedirectView createRedirectView( HttpServletRequest request, HttpServletResponse response ) {
        RedirectView redirect = new RedirectView( getRedirectUrl(), this.contextRelative, this.http10Compatible );
        redirect.setEncodingScheme( this.encodingScheme );
        return redirect;
    }

    protected Map<String,Object> createRequestParamMap( HttpServletRequest request, HttpServletResponse response, String attemptedPage ) {
        HashMap<String, Object> redirectMap = new HashMap<String, Object>( 1 );
        redirectMap.put( getAttemptedPageKeyName(), attemptedPage );
        return redirectMap;
    }

    protected Map<String,Object> storeInJSecuritySession( HttpServletRequest request, HttpServletResponse response, String attemptedPage ) {
        boolean boundToSession = false;

        SecurityContext securityContext = getSecurityContext( request, response );

        try {
            Session session = securityContext.getSession( false );
            if ( session != null ) {
                session.setAttribute( getAttemptedPageKeyName(), attemptedPage );
                boundToSession = true;
            } else {
                if ( log.isWarnEnabled() ) {
                    log.warn( "No JSecurity Session found bound to the current thread.  Attempted page cannot be " +
                        "set on the Session." );
                }
            }
        } catch ( InvalidSessionException e ) {
            if ( log.isInfoEnabled() ) {
                log.info( "Encountered an invalid Session while attempting to set the " +
                    "attempted page for authentication redirect.", e );
            }
        }

        if ( !boundToSession ) {
            if ( log.isInfoEnabled() ) {
                log.info( "Unable to set attempted page value on Session.  Defaulting to request parameter scheme." );
            }
            return createRequestParamMap( request, response, attemptedPage );
        } else {
            return null;
        }
    }

    protected Map<String,Object> storeInHttpSession( HttpServletRequest request, HttpServletResponse response, String attemptedPage ) {
        HttpSession httpSession = request.getSession();
        httpSession.setAttribute( getAttemptedPageKeyName(), attemptedPage );
        return null;
    }

    protected Map<String,Object> setSchemeAttemptedPage( HttpServletRequest request, HttpServletResponse response, String attemptedPage ) {
        AttemptedPageStorageScheme scheme = getAttemptedPageStorageScheme();
        if ( scheme == null ) {
            return null; //no attempted page to forward
        }

        switch ( scheme ) {
            case requestParameter:
                return createRequestParamMap( request, response, attemptedPage );
            case jsecuritySession:
                return storeInJSecuritySession( request, response, attemptedPage );
            case httpSession:
                return storeInHttpSession( request, response, attemptedPage );
            default:
                String msg = "getAttemptedPageStorageScheme() did not return an expected value, " +
                    "but was: [" + scheme.toString() + "]";
                throw new IllegalStateException( msg );
        }
    }

    protected String getAttemptedPage( HttpServletRequest request, HttpServletResponse response ) {
        StringBuffer attemptedPage = request.getRequestURL();
        String queryString = request.getQueryString();
        if ( queryString != null ) {
            attemptedPage.append( "?" );
            attemptedPage.append( queryString );
        }
        return attemptedPage.toString();
    }

    protected String getExcludedPath( HttpServletRequest request ) throws Exception {
        return request.getRequestURI();
    }

    protected boolean isPathExcluded( String requestedPath ) {
        for ( String excludedPath : excludedPaths ) {
            if ( requestedPath.indexOf( excludedPath ) != -1 ) {
                return true;
            }
        }
        return false;
    }

    protected boolean isExcluded( HttpServletRequest request, HttpServletResponse response ) throws Exception {
        String path = getExcludedPath( request );
        return isPathExcluded( path );
    }

    /**
     * Allows subclass implementations to add and/or override the model that will be encoded in the redirect.  Default
     * implementation just returns the <tt>redirectModel</tt> argument immediately.
     *
     * @param redirectModel the current redirect model, may be <tt>null</tt>
     * @param request       the incoming HttpServletRequest
     * @param response      the outgoing HttpServletResponse
     * @return the final redirect model that will be encoded in the redirect;
     */
    protected Map<String,Object> afterSchemeSet( Map<String,Object> redirectModel, HttpServletRequest request, HttpServletResponse response ) {
        return redirectModel;
    }

    protected boolean handleUnauthenticatedRequest( ServletRequest servletRequest, ServletResponse servletResponse ) throws IOException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        String attemptedPage = getAttemptedPage( request, response );

        if ( log.isDebugEnabled() ) {
            log.debug( "User is not allowed to access page [" + attemptedPage + "] without " +
                "first being authenticated.  Redirecting to login page [" +
                getRedirectUrl() + "]" );
        }

        RedirectView redirect = createRedirectView( request, response );

        Map<String,Object> redirectModel = setSchemeAttemptedPage( request, response, attemptedPage );

        redirectModel = afterSchemeSet( redirectModel, request, response );

        redirect.renderMergedOutputModel( redirectModel, request, response );

        return false;
    }

    protected boolean isAuthenticated( HttpServletRequest request, HttpServletResponse response ) throws Exception {
       SecurityContext securityContext = getSecurityContext( request, response );
        return securityContext.isAuthenticated();
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response ) throws Exception {
        if ( !isAuthenticated( request, response ) && !isExcluded( request, response ) ) {
            return handleUnauthenticatedRequest( request, response );
        }

        return true;
    }

    public void postHandle( HttpServletRequest request, HttpServletResponse response ) throws Exception {
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response, Exception exception ) throws Exception {
    }
}
