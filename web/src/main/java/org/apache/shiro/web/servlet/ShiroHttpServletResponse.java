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
package org.apache.shiro.web.servlet;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

/**
 * HttpServletResponse implementation to support URL Encoding of Shiro Session IDs.
 * <p/>
 * It is only used when using Shiro's native Session Management configuration (and not when using the Servlet
 * Container session configuration, which is Shiro's default in a web environment).  Because the servlet container
 * already performs url encoding of its own session ids, instances of this class are only needed when using Shiro
 * native sessions.
 * <p/>
 * Note that this implementation relies in part on source code from the Tomcat 6.x distribution for
 * encoding URLs for session ID URL Rewriting (we didn't want to re-invent the wheel).  Since Shiro is also
 * Apache 2.0 license, all regular licenses and conditions have remained in tact.
 *
 * @since 0.2
 */
public class ShiroHttpServletResponse extends HttpServletResponseWrapper {

    //TODO - complete JavaDoc

    private static final String DEFAULT_SESSION_ID_PARAMETER_NAME = ShiroHttpSession.DEFAULT_SESSION_ID_NAME;

    private ServletContext context = null;
    //the associated request
    private ShiroHttpServletRequest request = null;

    public ShiroHttpServletResponse(HttpServletResponse wrapped, ServletContext context, ShiroHttpServletRequest request) {
        super(wrapped);
        this.context = context;
        this.request = request;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public ServletContext getContext() {
        return context;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setContext(ServletContext context) {
        this.context = context;
    }

    public ShiroHttpServletRequest getRequest() {
        return request;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setRequest(ShiroHttpServletRequest request) {
        this.request = request;
    }

    /**
     * Encode the session identifier associated with this response
     * into the specified redirect URL, if necessary.
     *
     * @param url URL to be encoded
     */
    public String encodeRedirectURL(String url) {
        if (isEncodeable(toAbsolute(url))) {
            return toEncoded(url, request.getSession().getId());
        } else {
            return url;
        }
    }


    public String encodeRedirectUrl(String s) {
        return encodeRedirectURL(s);
    }


    /**
     * Encode the session identifier associated with this response
     * into the specified URL, if necessary.
     *
     * @param url URL to be encoded
     */
    public String encodeURL(String url) {
        String absolute = toAbsolute(url);
        if (isEncodeable(absolute)) {
            // W3c spec clearly said
            if (url.equalsIgnoreCase("")) {
                url = absolute;
            }
            return toEncoded(url, request.getSession().getId());
        } else {
            return url;
        }
    }

    public String encodeUrl(String s) {
        return encodeURL(s);
    }

    /**
     * Return <code>true</code> if the specified URL should be encoded with
     * a session identifier.  This will be true if all of the following
     * conditions are met:
     * <ul>
     * <li>The request we are responding to asked for a valid session
     * <li>The requested session ID was not received via a cookie
     * <li>The specified URL points back to somewhere within the web
     * application that is responding to this request
     * </ul>
     *
     * @param location Absolute URL to be validated
     * @return {@code true} if the specified URL should be encoded with a session identifier, {@code false} otherwise.
     */
    protected boolean isEncodeable(final String location) {

        // First check if URL rewriting is disabled globally
        if (Boolean.FALSE.equals(request.getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)))
            return (false);

        if (location == null)
            return (false);

        // Is this an intra-document reference?
        if (location.startsWith("#"))
            return (false);

        // Are we in a valid session that is not using cookies?
        final HttpServletRequest hreq = request;
        final HttpSession session = hreq.getSession(false);
        if (session == null)
            return (false);
        if (hreq.isRequestedSessionIdFromCookie())
            return (false);

        return doIsEncodeable(hreq, session, location);
    }

    private boolean doIsEncodeable(HttpServletRequest hreq, HttpSession session, String location) {
        // Is this a valid absolute URL?
        URL url;
        try {
            url = new URL(location);
        } catch (MalformedURLException e) {
            return (false);
        }

        // Does this URL match down to (and including) the context path?
        if (!hreq.getScheme().equalsIgnoreCase(url.getProtocol()))
            return (false);
        if (!hreq.getServerName().equalsIgnoreCase(url.getHost()))
            return (false);
        int serverPort = hreq.getServerPort();
        if (serverPort == -1) {
            if ("https".equals(hreq.getScheme()))
                serverPort = 443;
            else
                serverPort = 80;
        }
        int urlPort = url.getPort();
        if (urlPort == -1) {
            if ("https".equals(url.getProtocol()))
                urlPort = 443;
            else
                urlPort = 80;
        }
        if (serverPort != urlPort)
            return (false);

        String contextPath = getRequest().getContextPath();
        if (contextPath != null) {
            String file = url.getFile();
            if ((file == null) || !file.startsWith(contextPath))
                return (false);
            String tok = ";" + DEFAULT_SESSION_ID_PARAMETER_NAME + "=" + session.getId();
            if (file.indexOf(tok, contextPath.length()) >= 0)
                return (false);
        }

        // This URL belongs to our web application, so it is encodeable
        return (true);

    }


    /**
     * Convert (if necessary) and return the absolute URL that represents the
     * resource referenced by this possibly relative URL.  If this URL is
     * already absolute, return it unchanged.
     *
     * @param location URL to be (possibly) converted and then returned
     * @return resource location as an absolute url
     * @throws IllegalArgumentException if a MalformedURLException is
     *                                  thrown when converting the relative URL to an absolute one
     */
    private String toAbsolute(String location) {

        if (location == null)
            return (location);

        boolean leadingSlash = location.startsWith("/");

        if (leadingSlash || !hasScheme(location)) {

            StringBuilder buf = new StringBuilder();

            String scheme = request.getScheme();
            String name = request.getServerName();
            int port = request.getServerPort();

            try {
                buf.append(scheme).append("://").append(name);
                if ((scheme.equals("http") && port != 80)
                        || (scheme.equals("https") && port != 443)) {
                    buf.append(':').append(port);
                }
                if (!leadingSlash) {
                    String relativePath = request.getRequestURI();
                    int pos = relativePath.lastIndexOf('/');
                    relativePath = relativePath.substring(0, pos);

                    String encodedURI = URLEncoder.encode(relativePath, getCharacterEncoding());
                    buf.append(encodedURI).append('/');
                }
                buf.append(location);
            } catch (IOException e) {
                IllegalArgumentException iae = new IllegalArgumentException(location);
                iae.initCause(e);
                throw iae;
            }

            return buf.toString();

        } else {
            return location;
        }
    }

    /**
     * Determine if the character is allowed in the scheme of a URI.
     * See RFC 2396, Section 3.1
     *
     * @param c the character to check
     * @return {@code true} if the character is allowed in a URI scheme, {@code false} otherwise.
     */
    public static boolean isSchemeChar(char c) {
        return Character.isLetterOrDigit(c) ||
                c == '+' || c == '-' || c == '.';
    }


    /**
     * Returns {@code true} if the URI string has a {@code scheme} component, {@code false} otherwise.
     *
     * @param uri the URI string to check for a scheme component
     * @return {@code true} if the URI string has a {@code scheme} component, {@code false} otherwise.
     */
    private boolean hasScheme(String uri) {
        int len = uri.length();
        for (int i = 0; i < len; i++) {
            char c = uri.charAt(i);
            if (c == ':') {
                return i > 0;
            } else if (!isSchemeChar(c)) {
                return false;
            }
        }
        return false;
    }

    /**
     * Return the specified URL with the specified session identifier suitably encoded.
     *
     * @param url       URL to be encoded with the session id
     * @param sessionId Session id to be included in the encoded URL
     * @return the url with the session identifer properly encoded.
     */
    protected String toEncoded(String url, String sessionId) {

        if ((url == null) || (sessionId == null))
            return (url);

        String path = url;
        String query = "";
        String anchor = "";
        int question = url.indexOf('?');
        if (question >= 0) {
            path = url.substring(0, question);
            query = url.substring(question);
        }
        int pound = path.indexOf('#');
        if (pound >= 0) {
            anchor = path.substring(pound);
            path = path.substring(0, pound);
        }
        StringBuilder sb = new StringBuilder(path);
        if (sb.length() > 0) { // session id param can't be first.
            sb.append(";");
            sb.append(DEFAULT_SESSION_ID_PARAMETER_NAME);
            sb.append("=");
            sb.append(sessionId);
        }
        sb.append(anchor);
        sb.append(query);
        return (sb.toString());

    }
}
