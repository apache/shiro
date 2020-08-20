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

import org.apache.shiro.lang.util.StringUtils;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Default {@link Cookie Cookie} implementation.  'HttpOnly' is supported out of the box, even on
 * Servlet {@code 2.4} and {@code 2.5} container implementations, using raw header writing logic and not
 * {@link javax.servlet.http.Cookie javax.servlet.http.Cookie} objects (which only has 'HttpOnly' support in Servlet
 * {@code 2.6} specifications and above).
 *
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
    protected static final String MAXAGE_ATTRIBUTE_NAME = "Max-Age";
    protected static final String DOMAIN_ATTRIBUTE_NAME = "Domain";
    protected static final String VERSION_ATTRIBUTE_NAME = "Version";
    protected static final String COMMENT_ATTRIBUTE_NAME = "Comment";
    protected static final String SECURE_ATTRIBUTE_NAME = "Secure";
    protected static final String HTTP_ONLY_ATTRIBUTE_NAME = "HttpOnly";
    protected static final String SAME_SITE_ATTRIBUTE_NAME = "SameSite";

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
    private SameSiteOptions sameSite;

    public SimpleCookie() {
        this.maxAge = DEFAULT_MAX_AGE;
        this.version = DEFAULT_VERSION;
        this.httpOnly = true; //most of the cookies ever used by Shiro should be as secure as possible.
        this.sameSite = SameSiteOptions.LAX;
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
        this.sameSite = cookie.getSameSite();
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void setName(String name) {
        if (!StringUtils.hasText(name)) {
            throw new IllegalArgumentException("Name cannot be null/empty.");
        }
        this.name = name;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getDomain() {
        return domain;
    }

    @Override
    public void setDomain(String domain) {
        this.domain = domain;
    }

    @Override
    public String getPath() {
        return path;
    }

    @Override
    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public int getMaxAge() {
        return maxAge;
    }

    @Override
    public void setMaxAge(int maxAge) {
        this.maxAge = Math.max(DEFAULT_MAX_AGE, maxAge);
    }

    @Override
    public int getVersion() {
        return version;
    }

    @Override
    public void setVersion(int version) {
        this.version = Math.max(DEFAULT_VERSION, version);
    }

    @Override
    public boolean isSecure() {
        return secure;
    }

    @Override
    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    @Override
    public boolean isHttpOnly() {
        return httpOnly;
    }

    @Override
    public void setHttpOnly(boolean httpOnly) {
        this.httpOnly = httpOnly;
    }

    @Override
    public SameSiteOptions getSameSite() {
        return sameSite;
    }

    @Override
    public void setSameSite(SameSiteOptions sameSite) {
        this.sameSite = sameSite;
        if (this.sameSite == SameSiteOptions.NONE) {
            // do not allow invalid cookies. Only secure cookies are allowed if SameSite is set to NONE.
            setSecure(true);
        }
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

    @Override
    public void saveTo(HttpServletRequest request, HttpServletResponse response) {

        String name = getName();
        String value = getValue();
        String comment = getComment();
        String domain = getDomain();
        String path = calculatePath(request);
        int maxAge = getMaxAge();
        int version = getVersion();
        boolean secure = isSecure();
        boolean httpOnly = isHttpOnly();
        SameSiteOptions sameSite = getSameSite();

        addCookieHeader(response, name, value, comment, domain, path, maxAge, version, secure, httpOnly, sameSite);
    }

    private void addCookieHeader(HttpServletResponse response, String name, String value, String comment,
                                 String domain, String path, int maxAge, int version,
                                 boolean secure, boolean httpOnly, SameSiteOptions sameSite) {

        String headerValue = buildHeaderValue(name, value, comment, domain, path, maxAge, version, secure, httpOnly, sameSite);
        response.addHeader(COOKIE_HEADER_NAME, headerValue);

        if (log.isDebugEnabled()) {
            log.debug("Added HttpServletResponse Cookie [{}]", headerValue);
        }
    }

    /*
     * This implementation followed the grammar defined here for convenience:
     * <a href="http://github.com/abarth/http-state/blob/master/notes/2009-11-07-Yui-Naruse.txt">Cookie grammar</a>.
     *
     * @return the 'Set-Cookie' header value for this cookie instance.
     */

    protected String buildHeaderValue(String name, String value, String comment,
                                      String domain, String path, int maxAge, int version,
                                      boolean secure, boolean httpOnly) {

        return buildHeaderValue(name, value, comment, domain, path, maxAge, version, secure, httpOnly, getSameSite());
    }

    protected String buildHeaderValue(String name, String value, String comment,
                                      String domain, String path, int maxAge, int version,
                                      boolean secure, boolean httpOnly, SameSiteOptions sameSite) {

        if (!StringUtils.hasText(name)) {
            throw new IllegalStateException("Cookie name cannot be null/empty.");
        }

        StringBuilder sb = new StringBuilder(name).append(NAME_VALUE_DELIMITER);

        if (StringUtils.hasText(value)) {
            sb.append(value);
        }

        appendComment(sb, comment);
        appendDomain(sb, domain);
        appendPath(sb, path);
        appendExpires(sb, maxAge);
        appendVersion(sb, version);
        appendSecure(sb, secure);
        appendHttpOnly(sb, httpOnly);
        appendSameSite(sb, sameSite);

        return sb.toString();

    }

    private void appendComment(StringBuilder sb, String comment) {
        if (StringUtils.hasText(comment)) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(COMMENT_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(comment);
        }
    }

    private void appendDomain(StringBuilder sb, String domain) {
        if (StringUtils.hasText(domain)) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(DOMAIN_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(domain);
        }
    }

    private void appendPath(StringBuilder sb, String path) {
        if (StringUtils.hasText(path)) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(PATH_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(path);
        }
    }

    private void appendExpires(StringBuilder sb, int maxAge) {
        // if maxAge is negative, cookie should should expire when browser closes
	// Don't write the maxAge cookie value if it's negative - at least on Firefox it'll cause the 
	// cookie to be deleted immediately
        // Write the expires header used by older browsers, but may be unnecessary
        // and it is not by the spec, see http://www.faqs.org/rfcs/rfc2965.html
        // TODO consider completely removing the following 
        if (maxAge >= 0) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(MAXAGE_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(maxAge);
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

    private void appendVersion(StringBuilder sb, int version) {
        if (version > DEFAULT_VERSION) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(VERSION_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(version);
        }
    }

    private void appendSecure(StringBuilder sb, boolean secure) {
        if (secure) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(SECURE_ATTRIBUTE_NAME); //No value for this attribute
        }
    }

    private void appendHttpOnly(StringBuilder sb, boolean httpOnly) {
        if (httpOnly) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(HTTP_ONLY_ATTRIBUTE_NAME); //No value for this attribute
        }
    }

    private void appendSameSite(StringBuilder sb, SameSiteOptions sameSite) {
        if (sameSite != null) {
            sb.append(ATTRIBUTE_DELIMITER);
            sb.append(SAME_SITE_ATTRIBUTE_NAME).append(NAME_VALUE_DELIMITER).append(sameSite.toString().toLowerCase(Locale.ENGLISH));
        }
    }

    /**
     * Check whether the given {@code cookiePath} matches the {@code requestPath}
     *
     * @param cookiePath
     * @param requestPath
     * @return
     * @see <a href="https://tools.ietf.org/html/rfc6265#section-5.1.4">RFC 6265, Section 5.1.4 "Paths and Path-Match"</a>
     */
    private boolean pathMatches(String cookiePath, String requestPath) {
        if (!requestPath.startsWith(cookiePath)) {
            return false;
        }

        return requestPath.length() == cookiePath.length()
            || cookiePath.charAt(cookiePath.length() - 1) == '/'
            || requestPath.charAt(cookiePath.length()) == '/';
    }

    /**
     * Formats a date into a cookie date compatible string (Netscape's specification).
     *
     * @param date the date to format
     * @return an HTTP 1.0/1.1 Cookie compatible date string (GMT-based).
     */
    private static String toCookieDate(Date date) {
        TimeZone tz = TimeZone.getTimeZone(GMT_TIME_ZONE_ID);
        DateFormat fmt = new SimpleDateFormat(COOKIE_DATE_FORMAT_STRING, Locale.US);
        fmt.setTimeZone(tz);
        return fmt.format(date);
    }

    @Override
    public void removeFrom(HttpServletRequest request, HttpServletResponse response) {
        String name = getName();
        String value = DELETED_COOKIE_VALUE;
        String comment = null; //don't need to add extra size to the response - comments are irrelevant for deletions
        String domain = getDomain();
        String path = calculatePath(request);
        int maxAge = 0; //always zero for deletion
        int version = getVersion();
        boolean secure = isSecure();
        boolean httpOnly = false; //no need to add the extra text, plus the value 'deleteMe' is not sensitive at all
        SameSiteOptions sameSite = getSameSite();

        addCookieHeader(response, name, value, comment, domain, path, maxAge, version, secure, httpOnly, sameSite);

        log.trace("Removed '{}' cookie by setting maxAge=0", name);
    }

    @Override
    public String readValue(HttpServletRequest request, HttpServletResponse ignored) {
        String name = getName();
        String value = null;
        javax.servlet.http.Cookie cookie = getCookie(request, name);
        if (cookie != null) {
            // Validate that the cookie is used at the correct place.
            String path = StringUtils.clean(getPath());
            if (path != null && !pathMatches(path, request.getRequestURI())) {
                log.warn("Found '{}' cookie at path '{}', but should be only used for '{}'", 
                		new Object[] { name, Encode.forHtml(request.getRequestURI()), path});
            } else {
                value = cookie.getValue();
                log.debug("Found '{}' cookie value [{}]", name, Encode.forHtml(value));
            }
        } else {
            log.trace("No '{}' cookie value", name);
        }

        return value;
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
}
