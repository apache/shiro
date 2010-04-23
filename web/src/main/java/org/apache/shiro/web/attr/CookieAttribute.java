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
package org.apache.shiro.web.attr;

import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.beans.PropertyEditor;

import static org.apache.shiro.web.WebUtils.toHttp;

/**
 * A {@code CookieAttribute} stores an object as a {@link Cookie} for access on later requests.
 *
 * @author Les Hazlewood
 * @author Peter Ledbrook
 * @since 0.2
 * @deprecated in favor of {@link org.apache.shiro.web.servlet.Cookie} and {@link org.apache.shiro.web.servlet.SimpleCookie}
 *             usages.  THIS CLASS WILL BE DELETED PRIOR TO THE 1.0 RELEASE
 */
@Deprecated
public class CookieAttribute<T> extends AbstractWebAttribute<T> {

    //TODO - complete JavaDoc

    /**
     * Private internal log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(CookieAttribute.class);

    /**
     * The number of seconds in one year (= 60 * 60 * 24 * 365).
     */
    public static final int ONE_YEAR = 60 * 60 * 24 * 365;
    /**
     * This is the same value as Integer.MAX_VALUE, and while Tomcat does fine with cookie max age with this value,
     * Jetty apparently has problems with it.  If you're using Jetty, you might want to use the
     * {@link #ONE_YEAR ONE_YEAR} constant or another value.
     */
    public static final int INDEFINITE = Integer.MAX_VALUE;

    /**
     * {@code null}, indicating the cookie should be set on the request context root.
     */
    public static final String DEFAULT_PATH = null;

    /**
     * Root path to use when the path hasn't been set and request context root is empty or null.
     */
    public static final String ROOT_PATH = "/";
    /**
     * {@code -1}, indicating the cookie should expire when the browser closes.
     */
    public static final int DEFAULT_MAX_AGE = -1;

    /**
     * {@code -1} indicating that no version property should be set on the cookie.
     */
    public static final int DEFAULT_VERSION = -1;

    /**
     * Default value is {@code false}.
     */
    public static final boolean DEFAULT_SECURE = false;

    private String comment = null;
    private String domain = null;
    private int maxAge = DEFAULT_MAX_AGE;
    private String path = DEFAULT_PATH;
    private boolean secure = DEFAULT_SECURE;
    private int version = DEFAULT_VERSION;

    public CookieAttribute() {
    }

    /**
     * Constructs a {@code CookieAttribute} using a {@link Cookie Cookie} with the specified {@link Cookie#getName() name}
     * using the request context's path and with a {@link Cookie#setMaxAge(int) maxAge} of {@code -1}, indicating the
     * Cookie will persist until browser shutdown.
     *
     * @param name the Cookie {@link Cookie#getName() name}
     */
    public CookieAttribute(String name) {
        super(name);
    }

    /**
     * Constructs a {@code CookieAttribute} using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name} and {@link Cookie#getPath() path}.
     * <p/>
     * A {@code null} {@code path} value means the request context's path will be used by default.
     * <p/>
     * The Cookie's {@link Cookie#getMaxAge() maxAge} will be {@code -1}, indicating the Cookie will persist until
     * browser shutdown.
     *
     * @param name the Cookie {@link Cookie#getName() name}
     * @param path the Cookie {@link Cookie#setPath(String) path}.
     */
    public CookieAttribute(String name, String path) {
        super(name);
        setPath(path);
    }

    /**
     * Constructs a {@code CookieAttribute} using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name} and {@link Cookie#getMaxAge() maxAge}.
     * <p/>
     * The Cookie's {@link javax.servlet.http.Cookie#getPath() path} will be the {@code Request}'s
     * {@link javax.servlet.http.HttpServletRequest#getContextPath() context path}.
     *
     * @param name   the Cookie {@link javax.servlet.http.Cookie#getName() name};
     * @param maxAge the Cookie {@link Cookie#getMaxAge() maxAge}
     */
    public CookieAttribute(String name, int maxAge) {
        super(name);
        setMaxAge(maxAge);
    }

    /**
     * Constructs a {@code CookieAttribute} using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name}, {@link javax.servlet.http.Cookie#getPath() path}, and
     * {@link Cookie#getMaxAge() maxAge}.
     *
     * @param name   the Cookie {@link Cookie#getName() name}
     * @param path   the Cookie {@link Cookie#setPath(String) path}.
     * @param maxAge the Cookie {@link Cookie#getMaxAge() maxAge}
     */
    public CookieAttribute(String name, String path, int maxAge) {
        this(name, path);
        setMaxAge(maxAge);
    }

    /**
     * Constructs a {@code CookieAttribute} using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name}, {@link javax.servlet.http.Cookie#getPath() path}, and
     * {@link Cookie#getMaxAge() maxAge}, utilizing the specified {@code PropertyEditor} to perform value/string
     * conversion on the object stored as a cookie.
     *
     * @param name        the Cookie {@link Cookie#getName() name}
     * @param path        the Cookie {@link Cookie#setPath(String) path}.
     * @param maxAge      the Cookie {@link Cookie#getMaxAge() maxAge}
     * @param editorClass the {@code PropertyEditor} to perform value/string conversion on the object stored as a
     *                    Cookie.
     */
    public CookieAttribute(String name, String path, int maxAge, Class<? extends PropertyEditor> editorClass) {
        super(name, editorClass);
        setPath(path);
        setMaxAge(maxAge);
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

    /**
     * Returns the Cookie's {@link Cookie#getPath() path} setting.  If {@code null}, the {@code request}'s
     * {@link javax.servlet.http.HttpServletRequest#getContextPath() context path} will be used.
     * <p/>
     * The default is {@code null}.
     *
     * @return the Cookie's path, or {@code null} if the request's context path should be used as the path when the
     *         cookie is created.
     */
    public String getPath() {
        return path;
    }


    /**
     * Sets the Cookie's {@link Cookie#getPath() path} setting.  If the argument is {@code null}, the {@code request}'s
     * {@link javax.servlet.http.HttpServletRequest#getContextPath() context path} will be used.
     * <p/>
     * The default is {@code null}.
     *
     * @param path the Cookie's path, or {@code null} if the request's context path should be used as the path when the
     *             cookie is created.
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     * Returns the Cookie's {@link Cookie#setMaxAge(int) maxAge} setting.  Please see that JavaDoc for the semantics on
     * the repercussions of negative, zero, and positive values for the maxAge.
     * <p/>
     * The default value is {@code -1}, meaning the cookie will expire when the browser is closed.
     *
     * @return the Cookie's {@link Cookie#setMaxAge(int) maxAge}
     */
    public int getMaxAge() {
        return maxAge;
    }

    /**
     * Sets the Cookie's {@link Cookie#setMaxAge(int) maxAge} setting.  Please see that JavaDoc for the semantics on
     * the repercussions of negative, zero, and positive values for the maxAge.
     * <p/>
     * The default value is {@code -1}, meaning the cookie will expire when the browser is closed.
     *
     * @param maxAge the Cookie's {@link Cookie#setMaxAge(int) maxAge}
     */
    public void setMaxAge(int maxAge) {
        this.maxAge = maxAge;
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
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
    private static Cookie getCookie(HttpServletRequest request, String cookieName) {
        Cookie cookies[] = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(cookieName)) {
                    return cookie;
                }
            }
        }
        return null;
    }

    public T onRetrieveValue(ServletRequest request, ServletResponse response) {
        T value = null;

        String cookieName = getName();
        String stringValue;
        Cookie cookie = getCookie(toHttp(request), cookieName);
        if (cookie != null && cookie.getMaxAge() != 0) {
            stringValue = cookie.getValue();
            log.debug("Found string value [{}] from Cookie [{}]", stringValue, cookieName);
            value = fromStringValue(stringValue);
        } else {
            log.trace("No value found in request Cookies under cookie name [{}]", cookieName);
        }

        return value;
    }

    /**
     * Returns the Cookie's calculated path setting.  If the {@link Cookie#getPath() path} is {@code null}, then the
     * {@code request}'s {@link javax.servlet.http.HttpServletRequest#getContextPath() context path}
     * will be returned. If getContextPath() is the empty string or null then the ROOT_PATH constant is returned.
     *
     * @param request the incoming HttpServletRequest
     * @return the path to be used as the path when the cookie is created or removed
     */
    public String calculatePath(HttpServletRequest request) {
        String calculatePath = getPath() != null ? getPath() : request.getContextPath();

        //fix for http://issues.apache.org/jira/browse/JSEC-34:
        calculatePath = StringUtils.clean(calculatePath);
        if (calculatePath == null) {
            calculatePath = ROOT_PATH;
        }
        log.trace("calculated path: {}", calculatePath);
        return calculatePath;
    }

    public void onStoreValue(T value, ServletRequest servletRequest, ServletResponse servletResponse) {

        HttpServletRequest request = toHttp(servletRequest);
        HttpServletResponse response = toHttp(servletResponse);

        String name = getName();
        String comment = getComment();
        String domain = getDomain();
        int version = getVersion();
        int maxAge = getMaxAge();
        String path = calculatePath(request);

        //fix for http://issues.apache.org/jira/browse/JSEC-34:
        path = StringUtils.clean(path);
        if (path == null) {
            path = ROOT_PATH;
        }

        String stringValue = toStringValue(value);
        Cookie cookie = new Cookie(name, stringValue);
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

        response.addCookie(cookie);

        if (log.isDebugEnabled()) {
            log.debug("Added Cookie [{}] to path [{}] with value [{}] to the HttpServletResponse",
                    new Object[]{name, path, stringValue});
        }
    }

    public void removeValue(ServletRequest servletRequest, ServletResponse response) {
        HttpServletRequest request = toHttp(servletRequest);
        Cookie cookie = getCookie(request, getName());

        if (cookie != null) {
            cookie.setMaxAge(0);
            cookie.setValue("forgetme");
            //JSEC-94: Must set the path on the outgoing cookie (some browsers don't retain it from the
            //retrieved cookie?)
            // my testing shows none of these browsers will remove cookie if setPath() is not invoked: FF3, Chrome, IE7, Safari windows
            cookie.setPath(calculatePath(request));

            String domain = getDomain();
            if (domain != null) {
                cookie.setDomain(domain);
            }

            int version = getVersion();
            if (version > DEFAULT_VERSION) {
                cookie.setVersion(version);
            }

            cookie.setSecure(isSecure());
            toHttp(response).addCookie(cookie);
            log.trace("Removed cookie[" + getName() + "] with path [" + calculatePath(request) + "] from HttpServletResponse.");
        }
    }
}
