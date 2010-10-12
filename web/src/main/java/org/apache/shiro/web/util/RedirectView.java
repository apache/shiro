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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;

/**
 * View that redirects to an absolute, context relative, or current request
 * relative URL, exposing all model attributes as HTTP query parameters.
 * <p/>
 * A URL for this view is supposed to be a HTTP redirect URL, i.e.
 * suitable for HttpServletResponse's <code>sendRedirect</code> method, which
 * is what actually does the redirect if the HTTP 1.0 flag is on, or via sending
 * back an HTTP 303 code - if the HTTP 1.0 compatibility flag is off.
 * <p/>
 * Note that while the default value for the "contextRelative" flag is off,
 * you will probably want to almost always set it to true. With the flag off,
 * URLs starting with "/" are considered relative to the web server root, while
 * with the flag on, they are considered relative to the web application root.
 * Since most web apps will never know or care what their context path actually
 * is, they are much better off setting this flag to true, and submitting paths
 * which are to be considered relative to the web application root.
 * <p/>
 * Note that in a Servlet 2.2 environment, i.e. a servlet container which
 * is only compliant to the limits of this spec, this class will probably fail
 * when feeding in URLs which are not fully absolute, or relative to the current
 * request (no leading "/"), as these are the only two types of URL that
 * <code>sendRedirect</code> supports in a Servlet 2.2 environment.
 * <p/>
 * <em>This class was borrowed from a nearly identical version found in
 * the <a href="http://www.springframework.org/">Spring Framework</a>, with minor modifications to
 * avoid a dependency on Spring itself for a very small amount of code - we couldn't have done it better, and
 * don't want to repeat all of their great effort ;).
 * The original author names and copyright (Apache 2.0) has been left in place.  A special
 * thanks to Rod Johnson, Juergen Hoeller, and Colin Sampaleanu for making this available.</em>
 *
 * @see #setContextRelative
 * @see #setHttp10Compatible
 * @see javax.servlet.http.HttpServletResponse#sendRedirect
 * @since 0.2
 */
public class RedirectView {

    //TODO - complete JavaDoc

    /**
     * The default encoding scheme: UTF-8
     */
    public static final String DEFAULT_ENCODING_SCHEME = "UTF-8";

    private String url;

    private boolean contextRelative = false;

    private boolean http10Compatible = true;

    private String encodingScheme = DEFAULT_ENCODING_SCHEME;

    /**
     * Constructor for use as a bean.
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public RedirectView() {
    }

    /**
     * Create a new RedirectView with the given URL.
     * <p>The given URL will be considered as relative to the web server,
     * not as relative to the current ServletContext.
     *
     * @param url the URL to redirect to
     * @see #RedirectView(String, boolean)
     */
    public RedirectView(String url) {
        setUrl(url);
    }

    /**
     * Create a new RedirectView with the given URL.
     *
     * @param url             the URL to redirect to
     * @param contextRelative whether to interpret the given URL as
     *                        relative to the current ServletContext
     */
    public RedirectView(String url, boolean contextRelative) {
        this(url);
        this.contextRelative = contextRelative;
    }

    /**
     * Create a new RedirectView with the given URL.
     *
     * @param url              the URL to redirect to
     * @param contextRelative  whether to interpret the given URL as
     *                         relative to the current ServletContext
     * @param http10Compatible whether to stay compatible with HTTP 1.0 clients
     */
    public RedirectView(String url, boolean contextRelative, boolean http10Compatible) {
        this(url);
        this.contextRelative = contextRelative;
        this.http10Compatible = http10Compatible;
    }


    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Set whether to interpret a given URL that starts with a slash ("/")
     * as relative to the current ServletContext, i.e. as relative to the
     * web application root.
     * <p/>
     * Default is "false": A URL that starts with a slash will be interpreted
     * as absolute, i.e. taken as-is. If true, the context path will be
     * prepended to the URL in such a case.
     *
     * @param contextRelative whether to interpret a given URL that starts with a slash ("/")
     *                        as relative to the current ServletContext, i.e. as relative to the
     *                        web application root.
     * @see javax.servlet.http.HttpServletRequest#getContextPath
     */
    public void setContextRelative(boolean contextRelative) {
        this.contextRelative = contextRelative;
    }

    /**
     * Set whether to stay compatible with HTTP 1.0 clients.
     * <p>In the default implementation, this will enforce HTTP status code 302
     * in any case, i.e. delegate to <code>HttpServletResponse.sendRedirect</code>.
     * Turning this off will send HTTP status code 303, which is the correct
     * code for HTTP 1.1 clients, but not understood by HTTP 1.0 clients.
     * <p>Many HTTP 1.1 clients treat 302 just like 303, not making any
     * difference. However, some clients depend on 303 when redirecting
     * after a POST request; turn this flag off in such a scenario.
     *
     * @param http10Compatible whether to stay compatible with HTTP 1.0 clients.
     * @see javax.servlet.http.HttpServletResponse#sendRedirect
     */
    public void setHttp10Compatible(boolean http10Compatible) {
        this.http10Compatible = http10Compatible;
    }

    /**
     * Set the encoding scheme for this view. Default is UTF-8.
     *
     * @param encodingScheme the encoding scheme for this view. Default is UTF-8.
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public void setEncodingScheme(String encodingScheme) {
        this.encodingScheme = encodingScheme;
    }


    /**
     * Convert model to request parameters and redirect to the given URL.
     *
     * @param model    the model to convert
     * @param request  the incoming HttpServletRequest
     * @param response the outgoing HttpServletResponse
     * @throws java.io.IOException if there is a problem issuing the redirect
     * @see #appendQueryProperties
     * @see #sendRedirect
     */
    public final void renderMergedOutputModel(
            Map model, HttpServletRequest request, HttpServletResponse response) throws IOException {

        // Prepare name URL.
        StringBuilder targetUrl = new StringBuilder();
        if (this.contextRelative && getUrl().startsWith("/")) {
            // Do not apply context path to relative URLs.
            targetUrl.append(request.getContextPath());
        }
        targetUrl.append(getUrl());
        //change the following method to accept a StringBuilder instead of a StringBuilder for Shiro 2.x:
        appendQueryProperties(targetUrl, model, this.encodingScheme);

        sendRedirect(request, response, targetUrl.toString(), this.http10Compatible);
    }

    /**
     * Append query properties to the redirect URL.
     * Stringifies, URL-encodes and formats model attributes as query properties.
     *
     * @param targetUrl      the StringBuffer to append the properties to
     * @param model          Map that contains model attributes
     * @param encodingScheme the encoding scheme to use
     * @throws java.io.UnsupportedEncodingException if string encoding failed
     * @see #urlEncode
     * @see #queryProperties
     * @see #urlEncode(String, String)
     */
    protected void appendQueryProperties(StringBuilder targetUrl, Map model, String encodingScheme)
            throws UnsupportedEncodingException {

        // Extract anchor fragment, if any.
        // The following code does not use JDK 1.4's StringBuffer.indexOf(String)
        // method to retain JDK 1.3 compatibility.
        String fragment = null;
        int anchorIndex = targetUrl.toString().indexOf('#');
        if (anchorIndex > -1) {
            fragment = targetUrl.substring(anchorIndex);
            targetUrl.delete(anchorIndex, targetUrl.length());
        }

        // If there aren't already some parameters, we need a "?".
        boolean first = (getUrl().indexOf('?') < 0);
        Map queryProps = queryProperties(model);

        if (queryProps != null) {
            for (Object o : queryProps.entrySet()) {
                if (first) {
                    targetUrl.append('?');
                    first = false;
                } else {
                    targetUrl.append('&');
                }
                Map.Entry entry = (Map.Entry) o;
                String encodedKey = urlEncode(entry.getKey().toString(), encodingScheme);
                String encodedValue =
                        (entry.getValue() != null ? urlEncode(entry.getValue().toString(), encodingScheme) : "");
                targetUrl.append(encodedKey).append('=').append(encodedValue);
            }
        }

        // Append anchor fragment, if any, to end of URL.
        if (fragment != null) {
            targetUrl.append(fragment);
        }
    }

    /**
     * URL-encode the given input String with the given encoding scheme, using
     * {@link URLEncoder#encode(String, String) URLEncoder.encode(input, enc)}.
     *
     * @param input          the unencoded input String
     * @param encodingScheme the encoding scheme
     * @return the encoded output String
     * @throws UnsupportedEncodingException if thrown by the JDK URLEncoder
     * @see java.net.URLEncoder#encode(String, String)
     * @see java.net.URLEncoder#encode(String)
     */
    protected String urlEncode(String input, String encodingScheme) throws UnsupportedEncodingException {
        return URLEncoder.encode(input, encodingScheme);
    }

    /**
     * Determine name-value pairs for query strings, which will be stringified,
     * URL-encoded and formatted by appendQueryProperties.
     * <p/>
     * This implementation returns all model elements as-is.
     *
     * @param model the model elements for which to determine name-value pairs.
     * @return the name-value pairs for query strings.
     * @see #appendQueryProperties
     */
    protected Map queryProperties(Map model) {
        return model;
    }

    /**
     * Send a redirect back to the HTTP client
     *
     * @param request          current HTTP request (allows for reacting to request method)
     * @param response         current HTTP response (for sending response headers)
     * @param targetUrl        the name URL to redirect to
     * @param http10Compatible whether to stay compatible with HTTP 1.0 clients
     * @throws IOException if thrown by response methods
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected void sendRedirect(HttpServletRequest request, HttpServletResponse response,
                                String targetUrl, boolean http10Compatible) throws IOException {
        if (http10Compatible) {
            // Always send status code 302.
            response.sendRedirect(response.encodeRedirectURL(targetUrl));
        } else {
            // Correct HTTP status code is 303, in particular for POST requests.
            response.setStatus(303);
            response.setHeader("Location", response.encodeRedirectURL(targetUrl));
        }
    }

}
