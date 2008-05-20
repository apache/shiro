/*
 * Copyright 2008 Les Hazlewood and original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.util.StringUtils;
import org.jsecurity.util.ThreadContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

/**
 * Simple utility class for operations used across multiple class hierarchies in the web framework code.
 *
 * <p>Some methods in this class were copied from the Spring Framework so we didn't have to re-invent the wheel,
 * and in these cases, we have retained all license, copyright and author information.
 *
 * @author Les Hazlewood
 * @author Rod Johnson
 * @author Juergen Hoeller
 * @since 0.9
 */
public class WebUtils {

    private static final Log log = LogFactory.getLog(WebUtils.class);

    public static final String SERVLET_REQUEST_KEY = ServletRequest.class.getName() + "_JSECURITY_THREAD_CONTEXST_KEY";
    public static final String SERVLET_RESPONSE_KEY = ServletResponse.class.getName() + "_JSECURITY_THREAD_CONTEXT_KEY";

    /**
     * Standard Servlet 2.3+ spec request attributes for include URI and paths.
     * <p>If included via a RequestDispatcher, the current resource will see the
     * originating request. Its own URI and paths are exposed as request attributes.
     *
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
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
     *
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
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
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @see javax.servlet.ServletRequest#getCharacterEncoding
     */
    public static final String DEFAULT_CHARACTER_ENCODING = "ISO-8859-1";

    /**
     * Return the path within the web application for the given request.
     * <p>Detects include request URL if called within a RequestDispatcher include.
     *
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @param request current HTTP request
     * @return the path within the web application
     */
    public static String getPathWithinApplication(HttpServletRequest request) {
        String contextPath = getContextPath(request);
        String requestUri = getRequestUri(request);
        if (StringUtils.startsWithIgnoreCase(requestUri, contextPath)) {
            // Normal case: URI contains context path.
            String path = requestUri.substring(contextPath.length());
            return (StringUtils.hasText(path) ? path : "/");
        } else {
            // Special case: rather unusual.
            return requestUri;
        }
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
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @param request current HTTP request
     * @return the request URI
     */
    public static String getRequestUri(HttpServletRequest request) {
        String uri = (String) request.getAttribute(INCLUDE_REQUEST_URI_ATTRIBUTE);
        if (uri == null) {
            uri = request.getRequestURI();
        }
        return decodeAndCleanUriString(request, uri);
    }

    /**
     * Decode the supplied URI string and strips any extraneous portion after a ';'.
     *
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     */
    private static String decodeAndCleanUriString(HttpServletRequest request, String uri) {
        uri = decodeRequestString(request, uri);
        int semicolonIndex = uri.indexOf(';');
        return (semicolonIndex != -1 ? uri.substring(0, semicolonIndex) : uri);
    }

    /**
     * Return the context path for the given request, detecting an include request
     * URL if called within a RequestDispatcher include.
     * <p>As the value returned by <code>request.getContextPath()</code> is <i>not</i>
     * decoded by the servlet container, this method will decode it.
     *
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @param request current HTTP request
     * @return the context path
     */
    public static String getContextPath(HttpServletRequest request) {
        String contextPath = (String) request.getAttribute(org.springframework.web.util.WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE);
        if (contextPath == null) {
            contextPath = request.getContextPath();
        }
        if ("/".equals(contextPath)) {
            // Invalid case, but happens for includes on Jetty: silently adapt it.
            contextPath = "";
        }
        return decodeRequestString(request, contextPath);
    }

    /**
     * Decode the given source string with a URLDecoder. The encoding will be taken
     * from the request, falling back to the default "ISO-8859-1".
     * <p>The default implementation uses <code>URLDecoder.decode(input, enc)</code>.
     *
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @param request current HTTP request
     * @param source  the String to decode
     * @return the decoded String
     * @see org.springframework.web.util.WebUtils#DEFAULT_CHARACTER_ENCODING
     * @see javax.servlet.ServletRequest#getCharacterEncoding
     * @see java.net.URLDecoder#decode(String, String)
     * @see java.net.URLDecoder#decode(String)
     */
    @SuppressWarnings({"deprecation"})
    public static String decodeRequestString(HttpServletRequest request, String source) {
        String enc = determineEncoding(request);
        try {
            return URLDecoder.decode(source, enc);
        }
        catch (UnsupportedEncodingException ex) {
            if (log.isWarnEnabled()) {
                log.warn("Could not decode request string [" + source + "] with encoding '" + enc +
                        "': falling back to platform default encoding; exception message: " + ex.getMessage());
            }
            return URLDecoder.decode(source);
        }
    }

    /**
     * Determine the encoding for the given request.
     * Can be overridden in subclasses.
     * <p>The default implementation checks the request encoding,
     * falling back to the default encoding specified for this resolver.
     *
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
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

    /**
     * Convenience method that simplifies retrieval of a thread-bound ServletRequest.  If there is no
     * ServletRequest bound to the thread, this method returns <tt>null</tt>.  It is merely a convenient wrapper
     * for the following:
     * <pre>
     * return (ServletRequest)get( SERVLET_REQUEST_KEY );</pre>
     *
     * <p>This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindServletRequest() unbindServletRequest} instead.
     *
     * @return the ServletRequest bound to the thread, or <tt>null</tt> if there isn't one bound.
     * @since 0.2
     */
    public static ServletRequest getServletRequest() {
        return (ServletRequest) ThreadContext.get( SERVLET_REQUEST_KEY );
    }

    /**
     * Convenience method that simplifies binding a ServletRequest to the current thread (via the ThreadContext).
     *
     * <p>The method's existence is to help reduce casting in your own code and to simplify remembering of
     * ThreadContext key names.  The implementation is simple in that, if the servletRequest is not <tt>null</tt>,
     * it binds it to the thread, i.e.:
     *
     * <pre>
     * if (servletRequest != null) {
     *     ThreadContext.put( SERVLET_REQUEST_KEY, session );
     * }</pre>
     *
     * @param servletRequest the ServletRequest object to bind to the thread.  If the argument is null, nothing will be done.
     * @since 0.2
     */
    public static void bind( ServletRequest servletRequest ) {
        if ( servletRequest != null ) {
            ThreadContext.put( SERVLET_REQUEST_KEY, servletRequest );
        }
    }

    /**
     * Convenience method that simplifies removal of a thread-local ServletRequest from the thread.
     *
     * <p>The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     *
     * <pre>
     * return (ServletRequest)ThreadContext.remove( SERVLET_REQUEST_KEY );</pre>
     *
     * <p>If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later during
     * thread execution), you should use the {@link #getServletRequest() getServletRequest()} method for that purpose.
     *
     * @return the Session object previously bound to the thread, or <tt>null</tt> if there was none bound.
     * @since 0.2
     */
    public static ServletRequest unbindServletRequest() {
        return (ServletRequest)ThreadContext.remove( SERVLET_REQUEST_KEY );
    }

    /**
     * Convenience method that simplifies retrieval of a thread-bound ServletResponse.  If there is no
     * ServletResponse bound to the thread, this method returns <tt>null</tt>.  It is merely a convenient wrapper
     * for the following:
     * <pre>
     * return (ServletResponse)ThreadContext.get( SERVLET_RESPONSE_KEY );</pre>
     *
     * <p>This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindServletResponse() unbindServletResponse} instead.
     *
     * @return the ServletResponse bound to the thread, or <tt>null</tt> if there isn't one bound.
     * @since 0.2
     */
    public static ServletResponse getServletResponse() {
        return (ServletResponse)ThreadContext.get( SERVLET_RESPONSE_KEY );
    }

    /**
     * Convenience method that simplifies binding a ServletResponse to the thread via the ThreadContext.
     *
     * <p>The method's existence is to help reduce casting in your own code and to simplify remembering of
     * ThreadContext key names.  The implementation is simple in that, if the servletResponse is not <tt>null</tt>,
     * it binds it to the thread, i.e.:
     *
     * <pre>
     * if (servletResponse != null) {
     *     ThreadContext.put( SERVLET_RESPONSE_KEY, session );
     * }</pre>
     *
     * @param servletResponse the ServletResponse object to bind to the thread.  If the argument is null, nothing will be done.
     * @since 0.2
     */
    public static void bind( ServletResponse servletResponse ) {
        if ( servletResponse != null ) {
            ThreadContext.put( SERVLET_RESPONSE_KEY, servletResponse );
        }
    }

    /**
     * Convenience method that simplifies removal of a thread-local ServletResponse from the thread.
     *
     * <p>The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     *
     * <pre>
     * return (ServletResponse)ThreadContext.remove( SERVLET_RESPONSE_KEY );</pre>
     *
     * <p>If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later during
     * thread execution), you should use the {@link #getServletResponse() getServletResponse()} method for that purpose.
     *
     * @return the Session object previously bound to the thread, or <tt>null</tt> if there was none bound.
     * @since 0.2
     */
    public static ServletResponse unbindServletResponse() {
        return (ServletResponse)ThreadContext.remove( SERVLET_RESPONSE_KEY );
    }
}
