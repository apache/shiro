/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.web.util;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.web.env.EnvironmentLoader;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Map;

/**
 * Simple utility class for operations used across multiple class hierarchies in the web framework code.
 * <p/>
 * Some methods in this class were copied from the Spring Framework so we didn't have to re-invent the wheel,
 * and in these cases, we have retained all license, copyright and author information.
 *
 * @since 0.9
 */
public class WebUtils {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(WebUtils.class);

    public static final String SERVLET_REQUEST_KEY = ServletRequest.class.getName() + "_SHIRO_THREAD_CONTEXT_KEY";
    public static final String SERVLET_RESPONSE_KEY = ServletResponse.class.getName() + "_SHIRO_THREAD_CONTEXT_KEY";

    public static final String ALLOW_BACKSLASH = "org.apache.shiro.web.ALLOW_BACKSLASH";

    /**
     * {@link org.apache.shiro.session.Session Session} key used to save a request and later restore it, for example when redirecting to a
     * requested page after login, equal to {@code shiroSavedRequest}.
     */
    public static final String SAVED_REQUEST_KEY = "shiroSavedRequest";

    /**
     * Standard Servlet 2.3+ spec request attributes for include URI and paths.
     * <p>If included via a RequestDispatcher, the current resource will see the
     * originating request. Its own URI and paths are exposed as request attributes.
     */
    public static final String INCLUDE_REQUEST_URI_ATTRIBUTE = "javax.servlet.include.request_uri";
    public static final String INCLUDE_CONTEXT_PATH_ATTRIBUTE = "javax.servlet.include.context_path";
    public static final String INCLUDE_SERVLET_PATH_ATTRIBUTE = "javax.servlet.include.servlet_path";
    public static final String INCLUDE_PATH_INFO_ATTRIBUTE = "javax.servlet.include.path_info";
    public static final String INCLUDE_QUERY_STRING_ATTRIBUTE = "javax.servlet.include.query_string";

    /**
     * Standard Servlet 2.4+ spec request attributes for forward URI and paths.
     * <p>If forwarded to via a RequestDispatcher, the current resource will see its
     * own URI and paths. The originating URI and paths are exposed as request attributes.
     */
    public static final String FORWARD_REQUEST_URI_ATTRIBUTE = "javax.servlet.forward.request_uri";
    public static final String FORWARD_CONTEXT_PATH_ATTRIBUTE = "javax.servlet.forward.context_path";
    public static final String FORWARD_SERVLET_PATH_ATTRIBUTE = "javax.servlet.forward.servlet_path";
    public static final String FORWARD_PATH_INFO_ATTRIBUTE = "javax.servlet.forward.path_info";
    public static final String FORWARD_QUERY_STRING_ATTRIBUTE = "javax.servlet.forward.query_string";

    /**
     * Default character encoding to use when <code>request.getCharacterEncoding</code>
     * returns <code>null</code>, according to the Servlet spec.
     *
     * @see javax.servlet.ServletRequest#getCharacterEncoding
     */
    public static final String DEFAULT_CHARACTER_ENCODING = "ISO-8859-1";

    /**
     * Return the path within the web application for the given request.
     * Detects include request URL if called within a RequestDispatcher include.
     * <p/>
     * For example, for a request to URL
     * <p/>
     * <code>http://www.somehost.com/myapp/my/url.jsp</code>,
     * <p/>
     * for an application deployed to <code>/mayapp</code> (the application's context path), this method would return
     * <p/>
     * <code>/my/url.jsp</code>.
     *
     * @param request current HTTP request
     * @return the path within the web application
     */
    public static String getPathWithinApplication(HttpServletRequest request) {
        return normalize(removeSemicolon(getServletPath(request) + getPathInfo(request)));
    }

    /**
     * Return the request URI for the given request, detecting an include request
     * URL if called within a RequestDispatcher include.
     * <p>As the value returned by <code>request.getRequestURI()</code> is <i>not</i>
     * decoded by the servlet container, this method will decode it.
     * <p>The URI that the web container resolves <i>should</i> be correct, but some
     * containers like JBoss/Jetty incorrectly include ";" strings like ";jsessionid"
     * in the URI. This method cuts off such incorrect appendices.
     *
     * @param request current HTTP request
     * @return the request URI
     * @deprecated use getPathWithinApplication() to get the path minus the context path, or call HttpServletRequest.getRequestURI() directly from your code.
     */
    @Deprecated
    public static String getRequestUri(HttpServletRequest request) {
        String uri = (String) request.getAttribute(INCLUDE_REQUEST_URI_ATTRIBUTE);
        if (uri == null) {
            uri = request.getRequestURI();
        }
        return normalize(decodeAndCleanUriString(request, uri));
    }

    private static String getServletPath(HttpServletRequest request) {
        String servletPath = (String) request.getAttribute(INCLUDE_SERVLET_PATH_ATTRIBUTE);
        return servletPath != null ? servletPath : valueOrEmpty(request.getServletPath());
    }

    private static String getPathInfo(HttpServletRequest request) {
        String pathInfo = (String) request.getAttribute(INCLUDE_PATH_INFO_ATTRIBUTE);
        return pathInfo != null ? pathInfo : valueOrEmpty(request.getPathInfo());
    }

    private static String valueOrEmpty(String input) {
        if (input == null) {
            return "";
        }
        return input;
    }

    /**
     * Normalize a relative URI path that may have relative values ("/./",
     * "/../", and so on ) it it.  <strong>WARNING</strong> - This method is
     * useful only for normalizing application-generated paths.  It does not
     * try to perform security checks for malicious input.
     * Normalize operations were was happily taken from org.apache.catalina.util.RequestUtil in
     * Tomcat trunk, r939305
     *
     * @param path Relative path to be normalized
     * @return normalized path
     */
    public static String normalize(String path) {
        return normalize(path, Boolean.getBoolean(ALLOW_BACKSLASH));
    }

    /**
     * Normalize a relative URI path that may have relative values ("/./",
     * "/../", and so on ) it it.  <strong>WARNING</strong> - This method is
     * useful only for normalizing application-generated paths.  It does not
     * try to perform security checks for malicious input.
     * Normalize operations were was happily taken from org.apache.catalina.util.RequestUtil in
     * Tomcat trunk, r939305
     *
     * @param path             Relative path to be normalized
     * @param replaceBackSlash Should '\\' be replaced with '/'
     * @return normalized path
     */
    private static String normalize(String path, boolean replaceBackSlash) {

        if (path == null)
            return null;

        // Create a place for the normalized path
        String normalized = path;

        if (replaceBackSlash && normalized.indexOf('\\') >= 0)
            normalized = normalized.replace('\\', '/');

        if (normalized.equals("/."))
            return "/";

        // Add a leading "/" if necessary
        if (!normalized.startsWith("/"))
            normalized = "/" + normalized;

        // Resolve occurrences of "//" in the normalized path
        while (true) {
            int index = normalized.indexOf("//");
            if (index < 0)
                break;
            normalized = normalized.substring(0, index) +
                    normalized.substring(index + 1);
        }

        // Resolve occurrences of "/./" in the normalized path
        while (true) {
            int index = normalized.indexOf("/./");
            if (index < 0)
                break;
            normalized = normalized.substring(0, index) +
                    normalized.substring(index + 2);
        }

        // Resolve occurrences of "/../" in the normalized path
        while (true) {
            int index = normalized.indexOf("/../");
            if (index < 0)
                break;
            if (index == 0)
                return (null);  // Trying to go outside our context
            int index2 = normalized.lastIndexOf('/', index - 1);
            normalized = normalized.substring(0, index2) +
                    normalized.substring(index + 3);
        }

        // Return the normalized path that we have completed
        return (normalized);

    }


    /**
     * Decode the supplied URI string and strips any extraneous portion after a ';'.
     *
     * @param request the incoming HttpServletRequest
     * @param uri     the application's URI string
     * @return the supplied URI string stripped of any extraneous portion after a ';'.
     */
    private static String decodeAndCleanUriString(HttpServletRequest request, String uri) {
        uri = decodeRequestString(request, uri);
        return removeSemicolon(uri);
    }

    private static String removeSemicolon(String uri) {
        int semicolonIndex = uri.indexOf(';');
        return (semicolonIndex != -1 ? uri.substring(0, semicolonIndex) : uri);
    }

    /**
     * Return the context path for the given request, detecting an include request
     * URL if called within a RequestDispatcher include.
     * <p>As the value returned by <code>request.getContextPath()</code> is <i>not</i>
     * decoded by the servlet container, this method will decode it.
     *
     * @param request current HTTP request
     * @return the context path
     */
    public static String getContextPath(HttpServletRequest request) {
        String contextPath = (String) request.getAttribute(INCLUDE_CONTEXT_PATH_ATTRIBUTE);
        if (contextPath == null) {
            contextPath = request.getContextPath();
        }
        contextPath = normalize(decodeRequestString(request, contextPath));
        if ("/".equals(contextPath)) {
            // the normalize method will return a "/" and includes on Jetty, will also be a "/".
            contextPath = "";
        }
        return contextPath;
    }

    /**
     * Find the Shiro {@link WebEnvironment} for this web application, which is typically loaded via the
     * {@link org.apache.shiro.web.env.EnvironmentLoaderListener}.
     * <p/>
     * This implementation rethrows an exception that happened on environment startup to differentiate between a failed
     * environment startup and no environment at all.
     *
     * @param sc ServletContext to find the web application context for
     * @return the root WebApplicationContext for this web app
     * @throws IllegalStateException if the root WebApplicationContext could not be found
     * @see org.apache.shiro.web.env.EnvironmentLoader#ENVIRONMENT_ATTRIBUTE_KEY
     * @since 1.2
     */
    public static WebEnvironment getRequiredWebEnvironment(ServletContext sc)
            throws IllegalStateException {

        WebEnvironment we = getWebEnvironment(sc);
        if (we == null) {
            throw new IllegalStateException("No WebEnvironment found: no EnvironmentLoaderListener registered?");
        }
        return we;
    }

    /**
     * Find the Shiro {@link WebEnvironment} for this web application, which is typically loaded via
     * {@link org.apache.shiro.web.env.EnvironmentLoaderListener}.
     * <p/>
     * This implementation rethrows an exception that happened on environment startup to differentiate between a failed
     * environment startup and no environment at all.
     *
     * @param sc ServletContext to find the web application context for
     * @return the root WebApplicationContext for this web app, or <code>null</code> if none
     * @see org.apache.shiro.web.env.EnvironmentLoader#ENVIRONMENT_ATTRIBUTE_KEY
     * @since 1.2
     */
    public static WebEnvironment getWebEnvironment(ServletContext sc) {
        return getWebEnvironment(sc, EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY);
    }

    /**
     * Find the Shiro {@link WebEnvironment} for this web application.
     *
     * @param sc       ServletContext to find the web application context for
     * @param attrName the name of the ServletContext attribute to look for
     * @return the desired WebEnvironment for this web app, or <code>null</code> if none
     * @since 1.2
     */
    public static WebEnvironment getWebEnvironment(ServletContext sc, String attrName) {
        if (sc == null) {
            throw new IllegalArgumentException("ServletContext argument must not be null.");
        }
        Object attr = sc.getAttribute(attrName);
        if (attr == null) {
            return null;
        }
        if (attr instanceof RuntimeException) {
            throw (RuntimeException) attr;
        }
        if (attr instanceof Error) {
            throw (Error) attr;
        }
        if (attr instanceof Exception) {
            throw new IllegalStateException((Exception) attr);
        }
        if (!(attr instanceof WebEnvironment)) {
            throw new IllegalStateException("Context attribute is not of type WebEnvironment: " + attr);
        }
        return (WebEnvironment) attr;
    }


    /**
     * Decode the given source string with a URLDecoder. The encoding will be taken
     * from the request, falling back to the default "ISO-8859-1".
     * <p>The default implementation uses <code>URLDecoder.decode(input, enc)</code>.
     *
     * @param request current HTTP request
     * @param source  the String to decode
     * @return the decoded String
     * @see #DEFAULT_CHARACTER_ENCODING
     * @see javax.servlet.ServletRequest#getCharacterEncoding
     * @see java.net.URLDecoder#decode(String, String)
     * @see java.net.URLDecoder#decode(String)
     */
    @SuppressWarnings({"deprecation"})
    public static String decodeRequestString(HttpServletRequest request, String source) {
        String enc = determineEncoding(request);
        try {
            return URLDecoder.decode(source, enc);
        } catch (UnsupportedEncodingException ex) {
            if (log.isWarnEnabled()) {
                log.warn("Could not decode request string [" + Encode.forHtml(source) + "] with encoding '" + Encode.forHtml(enc) +
                        "': falling back to platform default encoding; exception message: " + ex.getMessage());
            }
            return URLDecoder.decode(source);
        }
    }

    /**
     * Determine the encoding for the given request.
     * Can be overridden in subclasses.
     * <p>The default implementation checks the request's
     * {@link ServletRequest#getCharacterEncoding() character encoding}, and if that
     * <code>null</code>, falls back to the {@link #DEFAULT_CHARACTER_ENCODING}.
     *
     * @param request current HTTP request
     * @return the encoding for the request (never <code>null</code>)
     * @see javax.servlet.ServletRequest#getCharacterEncoding()
     */
    protected static String determineEncoding(HttpServletRequest request) {
        String enc = request.getCharacterEncoding();
        if (enc == null) {
            enc = DEFAULT_CHARACTER_ENCODING;
        }
        return enc;
    }

    /*
     * Returns {@code true} IFF the specified {@code SubjectContext}:
     * <ol>
     * <li>A {@link WebSubjectContext} instance</li>
     * <li>The {@code WebSubjectContext}'s request/response pair are not null</li>
     * <li>The request is an {@link HttpServletRequest} instance</li>
     * <li>The response is an {@link HttpServletResponse} instance</li>
     * </ol>
     *
     * @param context the SubjectContext to check to see if it is HTTP compatible.
     * @return {@code true} IFF the specified context has HTTP request/response objects, {@code false} otherwise.
     * @since 1.0
     */

    public static boolean isWeb(Object requestPairSource) {
        return requestPairSource instanceof RequestPairSource && isWeb((RequestPairSource) requestPairSource);
    }

    public static boolean isHttp(Object requestPairSource) {
        return requestPairSource instanceof RequestPairSource && isHttp((RequestPairSource) requestPairSource);
    }

    public static ServletRequest getRequest(Object requestPairSource) {
        if (requestPairSource instanceof RequestPairSource) {
            return ((RequestPairSource) requestPairSource).getServletRequest();
        }
        return null;
    }

    public static ServletResponse getResponse(Object requestPairSource) {
        if (requestPairSource instanceof RequestPairSource) {
            return ((RequestPairSource) requestPairSource).getServletResponse();
        }
        return null;
    }

    public static HttpServletRequest getHttpRequest(Object requestPairSource) {
        ServletRequest request = getRequest(requestPairSource);
        if (request instanceof HttpServletRequest) {
            return (HttpServletRequest) request;
        }
        return null;
    }

    public static HttpServletResponse getHttpResponse(Object requestPairSource) {
        ServletResponse response = getResponse(requestPairSource);
        if (response instanceof HttpServletResponse) {
            return (HttpServletResponse) response;
        }
        return null;
    }

    private static boolean isWeb(RequestPairSource source) {
        ServletRequest request = source.getServletRequest();
        ServletResponse response = source.getServletResponse();
        return request != null && response != null;
    }

    private static boolean isHttp(RequestPairSource source) {
        ServletRequest request = source.getServletRequest();
        ServletResponse response = source.getServletResponse();
        return request instanceof HttpServletRequest && response instanceof HttpServletResponse;
    }

    /**
     * Returns {@code true} if a session is allowed to be created for a subject-associated request, {@code false}
     * otherwise.
     * <p/>
     * <b>This method exists for Shiro's internal framework needs and should never be called by Shiro end-users.  It
     * could be changed/removed at any time.</b>
     *
     * @param requestPairSource a {@link RequestPairSource} instance, almost always a
     *                          {@link org.apache.shiro.web.subject.WebSubject WebSubject} instance.
     * @return {@code true} if a session is allowed to be created for a subject-associated request, {@code false}
     *         otherwise.
     */
    public static boolean _isSessionCreationEnabled(Object requestPairSource) {
        if (requestPairSource instanceof RequestPairSource) {
            RequestPairSource source = (RequestPairSource) requestPairSource;
            return _isSessionCreationEnabled(source.getServletRequest());
        }
        return true; //by default
    }

    /**
     * Returns {@code true} if a session is allowed to be created for a subject-associated request, {@code false}
     * otherwise.
     * <p/>
     * <b>This method exists for Shiro's internal framework needs and should never be called by Shiro end-users.  It
     * could be changed/removed at any time.</b>
     *
     * @param request incoming servlet request.
     * @return {@code true} if a session is allowed to be created for a subject-associated request, {@code false}
     *         otherwise.
     */
    public static boolean _isSessionCreationEnabled(ServletRequest request) {
        if (request != null) {
            Object val = request.getAttribute(DefaultSubjectContext.SESSION_CREATION_ENABLED);
            if (val != null && val instanceof Boolean) {
                return (Boolean) val;
            }
        }
        return true; //by default
    }

    /**
     * A convenience method that merely casts the incoming <code>ServletRequest</code> to an
     * <code>HttpServletRequest</code>:
     * <p/>
     * <code>return (HttpServletRequest)request;</code>
     * <p/>
     * Logic could be changed in the future for logging or throwing an meaningful exception in
     * non HTTP request environments (e.g. Portlet API).
     *
     * @param request the incoming ServletRequest
     * @return the <code>request</code> argument casted to an <code>HttpServletRequest</code>.
     */
    public static HttpServletRequest toHttp(ServletRequest request) {
        return (HttpServletRequest) request;
    }

    /**
     * A convenience method that merely casts the incoming <code>ServletResponse</code> to an
     * <code>HttpServletResponse</code>:
     * <p/>
     * <code>return (HttpServletResponse)response;</code>
     * <p/>
     * Logic could be changed in the future for logging or throwing an meaningful exception in
     * non HTTP request environments (e.g. Portlet API).
     *
     * @param response the outgoing ServletResponse
     * @return the <code>response</code> argument casted to an <code>HttpServletResponse</code>.
     */
    public static HttpServletResponse toHttp(ServletResponse response) {
        return (HttpServletResponse) response;
    }

    /**
     * Redirects the current request to a new URL based on the given parameters.
     *
     * @param request          the servlet request.
     * @param response         the servlet response.
     * @param url              the URL to redirect the user to.
     * @param queryParams      a map of parameters that should be set as request parameters for the new request.
     * @param contextRelative  true if the URL is relative to the servlet context path, or false if the URL is absolute.
     * @param http10Compatible whether to stay compatible with HTTP 1.0 clients.
     * @throws java.io.IOException if thrown by response methods.
     */
    public static void issueRedirect(ServletRequest request, ServletResponse response, String url, Map queryParams, boolean contextRelative, boolean http10Compatible) throws IOException {
        RedirectView view = new RedirectView(url, contextRelative, http10Compatible);
        view.renderMergedOutputModel(queryParams, toHttp(request), toHttp(response));
    }

    /**
     * Redirects the current request to a new URL based on the given parameters and default values
     * for unspecified parameters.
     *
     * @param request  the servlet request.
     * @param response the servlet response.
     * @param url      the URL to redirect the user to.
     * @throws java.io.IOException if thrown by response methods.
     */
    public static void issueRedirect(ServletRequest request, ServletResponse response, String url) throws IOException {
        issueRedirect(request, response, url, null, true, true);
    }

    /**
     * Redirects the current request to a new URL based on the given parameters and default values
     * for unspecified parameters.
     *
     * @param request     the servlet request.
     * @param response    the servlet response.
     * @param url         the URL to redirect the user to.
     * @param queryParams a map of parameters that should be set as request parameters for the new request.
     * @throws java.io.IOException if thrown by response methods.
     */
    public static void issueRedirect(ServletRequest request, ServletResponse response, String url, Map queryParams) throws IOException {
        issueRedirect(request, response, url, queryParams, true, true);
    }

    /**
     * Redirects the current request to a new URL based on the given parameters and default values
     * for unspecified parameters.
     *
     * @param request         the servlet request.
     * @param response        the servlet response.
     * @param url             the URL to redirect the user to.
     * @param queryParams     a map of parameters that should be set as request parameters for the new request.
     * @param contextRelative true if the URL is relative to the servlet context path, or false if the URL is absolute.
     * @throws java.io.IOException if thrown by response methods.
     */
    public static void issueRedirect(ServletRequest request, ServletResponse response, String url, Map queryParams, boolean contextRelative) throws IOException {
        issueRedirect(request, response, url, queryParams, contextRelative, true);
    }

    /**
     * <p>Checks to see if a request param is considered true using a loose matching strategy for
     * general values that indicate that something is true or enabled, etc.</p>
     * <p/>
     * <p>Values that are considered "true" include (case-insensitive): true, t, 1, enabled, y, yes, on.</p>
     *
     * @param request   the servlet request
     * @param paramName @return true if the param value is considered true or false if it isn't.
     * @return true if the given parameter is considered "true" - false otherwise.
     */
    public static boolean isTrue(ServletRequest request, String paramName) {
        String value = getCleanParam(request, paramName);
        return value != null &&
                (value.equalsIgnoreCase("true") ||
                        value.equalsIgnoreCase("t") ||
                        value.equalsIgnoreCase("1") ||
                        value.equalsIgnoreCase("enabled") ||
                        value.equalsIgnoreCase("y") ||
                        value.equalsIgnoreCase("yes") ||
                        value.equalsIgnoreCase("on"));
    }

    /**
     * Convenience method that returns a request parameter value, first running it through
     * {@link StringUtils#clean(String)}.
     *
     * @param request   the servlet request.
     * @param paramName the parameter name.
     * @return the clean param value, or null if the param does not exist or is empty.
     */
    public static String getCleanParam(ServletRequest request, String paramName) {
        return StringUtils.clean(request.getParameter(paramName));
    }

    public static void saveRequest(ServletRequest request) {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        HttpServletRequest httpRequest = toHttp(request);
        SavedRequest savedRequest = new SavedRequest(httpRequest);
        session.setAttribute(SAVED_REQUEST_KEY, savedRequest);
    }

    public static SavedRequest getAndClearSavedRequest(ServletRequest request) {
        SavedRequest savedRequest = getSavedRequest(request);
        if (savedRequest != null) {
            Subject subject = SecurityUtils.getSubject();
            Session session = subject.getSession();
            session.removeAttribute(SAVED_REQUEST_KEY);
        }
        return savedRequest;
    }

    public static SavedRequest getSavedRequest(ServletRequest request) {
        SavedRequest savedRequest = null;
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession(false);
        if (session != null) {
            savedRequest = (SavedRequest) session.getAttribute(SAVED_REQUEST_KEY);
        }
        return savedRequest;
    }

    /**
     * Redirects the to the request url from a previously
     * {@link #saveRequest(javax.servlet.ServletRequest) saved} request, or if there is no saved request, redirects the
     * end user to the specified {@code fallbackUrl}.  If there is no saved request or fallback url, this method
     * throws an {@link IllegalStateException}.
     * <p/>
     * This method is primarily used to support a common login scenario - if an unauthenticated user accesses a
     * page that requires authentication, it is expected that request is
     * {@link #saveRequest(javax.servlet.ServletRequest) saved} first and then redirected to the login page. Then,
     * after a successful login, this method can be called to redirect them back to their originally requested URL, a
     * nice usability feature.
     *
     * @param request     the incoming request
     * @param response    the outgoing response
     * @param fallbackUrl the fallback url to redirect to if there is no saved request available.
     * @throws IllegalStateException if there is no saved request and the {@code fallbackUrl} is {@code null}.
     * @throws IOException           if there is an error redirecting
     * @since 1.0
     */
    public static void redirectToSavedRequest(ServletRequest request, ServletResponse response, String fallbackUrl)
            throws IOException {
        String successUrl = null;
        boolean contextRelative = true;
        SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);
        if (savedRequest != null && savedRequest.getMethod().equalsIgnoreCase(AccessControlFilter.GET_METHOD)) {
            successUrl = savedRequest.getRequestUrl();
            contextRelative = false;
        }

        if (successUrl == null) {
            successUrl = fallbackUrl;
        }

        if (successUrl == null) {
            throw new IllegalStateException("Success URL not available via saved request or via the " +
                    "successUrlFallback method parameter. One of these must be non-null for " +
                    "issueSuccessRedirect() to work.");
        }

        WebUtils.issueRedirect(request, response, successUrl, null, contextRelative);
    }

}
