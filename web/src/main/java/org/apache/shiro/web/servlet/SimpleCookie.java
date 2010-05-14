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

import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * TODO - Class JavaDoc
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class SimpleCookie implements Cookie {

    /**
     * {@code -1}, indicating the cookie should expire when the browser closes.
     */
    public static final int DEFAULT_MAX_AGE = -1;

    /**
     * {@code -1} indicating that no version property should be set on the cookie.
     */
    public static final int DEFAULT_VERSION = -1;

    //These constants are protected on purpose so that the test case can use them
    protected static final String NAME_VALUE_DELIMITER = "=";
    protected static final String ATTRIBUTE_DELIMITER = "; ";
    protected static final long DAY_MILLIS = 86400000; //1 day = 86,400,000 milliseconds
    protected static final String GMT_TIME_ZONE_ID = "GMT";
    protected static final String COOKIE_DATE_FORMAT_STRING = "EEE, dd-MMM-yyyy HH:mm:ss z";

    protected static final String COOKIE_HEADER_NAME = "Set-Cookie";
    protected static final String PATH_ATTRIBUTE_NAME = "Path";
    protected static final String EXPIRES_ATTRIBUTE_NAME = "Expires";
    protected static final String DOMAIN_ATTRIBUTE_NAME = "Domain";
    protected static final String VERSION_ATTRIBUTE_NAME = "Version";
    protected static final String COMMENT_ATTRIBUTE_NAME = "Comment";
    protected static final String SECURE_ATTRIBUTE_NAME = "Secure";
    protected static final String HTTP_ONLY_ATTRIBUTE_NAME = "HttpOnly";

    private static final transient Logger log = LoggerFactory.getLogger(SimpleCookie.class);

    private String name;
    private String value;
    private String comment;
    private String domain;
    private String path;
    private int maxAge;
    private int version;
    private boolean secure;
    private boolean httpOnly;

    public SimpleCookie() {
        this.maxAge = DEFAULT_MAX_AGE;
        this.version = DEFAULT_VERSION;
        this.httpOnly = true; //most of the cookies ever used by Shiro should be as secure as possible.
    }

    public SimpleCookie(String name) {
        this();
        this.name = name;
    }

    public SimpleCookie(Cookie cookie) {
        this.name = cookie.getName();
        this.value = cookie.getValue();
        this.comment = cookie.getComment();
        this.domain = cookie.getDomain();
        this.path = cookie.getPath();
        this.maxAge = Math.max(DEFAULT_MAX_AGE, cookie.getMaxAge());
        this.version = Math.max(DEFAULT_VERSION, cookie.getVersion());
        this.secure = cookie.isSecure();
        this.httpOnly = cookie.isHttpOnly();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (!StringUtils.hasText(name)) {
            throw new IllegalArgumentException("Name cannot be null/empty.");
        }
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public int getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(int maxAge) {
        this.maxAge = Math.max(DEFAULT_MAX_AGE, maxAge);
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = Math.max(DEFAULT_VERSION, version);
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    public boolean isHttpOnly() {
        return httpOnly;
    }

    public void setHttpOnly(boolean httpOnly) {
        this.httpOnly = httpOnly;
    }

    /**
     * Returns the Cookie's calculated path setting.  If the {@link javax.servlet.http.Cookie#getPath() path} is {@code null}, then the
     * {@code request}'s {@link javax.servlet.http.HttpServletRequest#getContextPath() context path}
     * will be returned. If getContextPath() is the empty string or null then the ROOT_PATH constant is returned.
     *
     * @param request the incoming HttpServletRequest
     * @return the path to be used as the path when the cookie is created or removed
     */
    private String calculatePath(HttpServletRequest request) {
        String path = StringUtils.clean(getPath());
        if (!StringUtils.hasText(path)) {
            path = StringUtils.clean(request.getContextPath());
        }

        //fix for http://issues.apache.org/jira/browse/SHIRO-9:
        if (path == null) {
            path = ROOT_PATH;
        }
        log.trace("calculated path: {}", path);
        return path;
    }

    public void saveTo(HttpServletRequest request, HttpServletResponse response) {

        /*String name = getName();
        String value = getValue();
        String comment = getComment();
        String domain = getDomain();
        int version = getVersion();
        int maxAge = getMaxAge();
        String path = calculatePath(request);

        javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie(name, value);
        cookie.setMaxAge(maxAge);
        cookie.setPath(path);

        if (comment != null) {
            cookie.setComment(comment);
        }
        if (domain != null) {
            cookie.setDomain(domain);
        }
        if (version > DEFAULT_VERSION) {
            cookie.setVersion(version);
        }

        if (isSecure()) {
            cookie.setSecure(true);
        }

        response.addCookie(cookie);*/

        String headerValue = buildHeaderValue(request);
        response.addHeader(COOKIE_HEADER_NAME, headerValue);

        if (log.isDebugEnabled()) {
            log.debug("Added HttpServletResponse Cookie [{}]", headerValue);
        }
    }

    /**
     * This implementation followed the grammar defined here for convenience:
     * <a href="http://github.com/abarth/http-state/blob/master/notes/2009-11-07-Yui-Naruse.txt">Cookie grammar</a>.
     *
     * @param request the incoming request
     * @return the 'Set-Cookie' header value for this cookie instance.
     */
    private String buildHeaderValue(HttpServletRequest request) {
        String name = getName();
        if (!StringUtils.hasText(name)) {
            throw new IllegalStateException("Cookie name cannot be null/empty.");
        }

        StringBuffer sb = new StringBuffer(name).append(NAME_VALUE_DELIMITER);

        String value = getValue();
        if (StringUtils.hasText(value)) {
            sb.append(value);
        }

        appendPath(sb, request);
        appendDomain(sb);
        appendExpires(sb);
        appendVersion(sb);
        appendComment(sb);
        appendSecure(sb);
        appendHttpOnly(sb);

        return sb.toString();
    }

    private void appendPath(StringBuffer sb, HttpServletRequest request) {
        String path = calculatePath(request);
        if (StringUtils.hasText(path)) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(PATH_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(path);
        }
    }

    private void appendDomain(StringBuffer sb) {
        String domain = getDomain();
        if (StringUtils.hasText(domain)) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(DOMAIN_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(domain);
        }
    }

    private void appendExpires(StringBuffer sb) {
        int maxAge = getMaxAge();
        if (maxAge > DEFAULT_MAX_AGE) {
            sb.append(ATTRIBUTE_DELIMITER);
            Date expires;
            if (maxAge == 0) {
                //delete the cookie by specifying a time in the past (1 day ago):
                expires = new Date(System.currentTimeMillis() - DAY_MILLIS);
            } else {
                //Value is in seconds.  So take 'now' and add that many seconds, and that's our expiration date:
                Calendar cal = Calendar.getInstance();
                cal.add(Calendar.SECOND, maxAge);
                expires = cal.getTime();
            }
            String formatted = toCookieDate(expires);
            sb.append(EXPIRES_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(formatted);
        }
    }

    private void appendVersion(StringBuffer sb) {
        int version = getVersion();
        if (version > DEFAULT_VERSION) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(VERSION_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(version);
        }
    }

    private void appendComment(StringBuffer sb) {
        String comment = getComment();
        if (StringUtils.hasText(comment)) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(COMMENT_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(comment);
        }
    }

    private void appendSecure(StringBuffer sb) {
        if (isSecure()) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(SECURE_ATTRIBUTE_NAME); //No value for this attribute
        }
    }

    private void appendHttpOnly(StringBuffer sb) {
        if (isHttpOnly()) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(HTTP_ONLY_ATTRIBUTE_NAME); //No value for this attribute
        }
    }

    /**
     * Formats a date into a cookie date compatible string (Netscape's specification).
     *
     * @param date the date to format
     * @return an HTTP 1.0/1.1 Cookie compatible date string (GMT-based).
     */
    private static String toCookieDate(Date date) {
        TimeZone tz = TimeZone.getTimeZone(GMT_TIME_ZONE_ID);
        DateFormat fmt = new SimpleDateFormat(COOKIE_DATE_FORMAT_STRING);
        fmt.setTimeZone(tz);
        return fmt.format(date);
    }

    /**
     * Returns the cookie with the given name from the request or {@code null} if no cookie
     * with that name could be found.
     *
     * @param request    the current executing http request.
     * @param cookieName the name of the cookie to find and return.
     * @return the cookie with the given name from the request or {@code null} if no cookie
     *         with that name could be found.
     */
    private static javax.servlet.http.Cookie getCookie(HttpServletRequest request, String cookieName) {
        javax.servlet.http.Cookie cookies[] = request.getCookies();
        if (cookies != null) {
            for (javax.servlet.http.Cookie cookie : cookies) {
                if (cookie.getName().equals(cookieName)) {
                    return cookie;
                }
            }
        }
        return null;
    }

    public void removeFrom(HttpServletRequest request, HttpServletResponse response) {
        javax.servlet.http.Cookie cookie = getCookie(request, getName());

        if (cookie != null) {
            cookie.setMaxAge(0);
            cookie.setValue("deleteMe");

            // JSEC-94: Must set the path on the outgoing cookie (some browsers don't retain it from the
            // retrieved cookie?)
            // Testing shows none of these browsers will remove cookie if setPath() is not invoked:
            // FF3, Chrome, IE7, Safari windows
            String path = calculatePath(request);
            cookie.setPath(path);

            String domain = getDomain();
            if (StringUtils.hasText(domain)) {
                cookie.setDomain(domain);
            }

            response.addCookie(cookie);
            log.trace("Removed cookie[" + getName() + "] with path [" + path + "] from HttpServletResponse.");
        }
    }

    public String readValue(HttpServletRequest request, HttpServletResponse ignored) {
        String name = getName();
        String value = null;
        javax.servlet.http.Cookie cookie = getCookie(request, name);
        if (cookie != null) {
            value = cookie.getValue();
            log.debug("Found string value [{}] from Cookie [{}]", value, name);
        } else {
            log.trace("No value found in request Cookies under cookie name [{}]", name);
        }

        return value;
    }
}
