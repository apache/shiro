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
package org.jsecurity.web.attr;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import static org.jsecurity.web.WebUtils.toHttp;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.beans.PropertyEditor;

/**
 * A <tt>CookieAttribute</tt> stores an object as a {@link Cookie} for access on later requests.
 *
 * @author Les Hazlewood
 * @author Peter Ledbrook
 * @since 0.2
 */
public class CookieAttribute<T> extends AbstractWebAttribute<T> {

    //TODO - complete JavaDoc
    
    /** Private internal log instance. */
    private static final Log log = LogFactory.getLog(CookieAttribute.class);    

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
     * <code>null</code>, indicating the cookie should be set on the request context root.
     */
    public static final String DEFAULT_PATH = null;
    /**
     * <code>-1</code>, indicating the cookie should expire when the browser closes.
     */
    public static final int DEFAULT_MAX_AGE = -1;
    /**
     * Default value is <code>false</code>.
     */
    public static final boolean DEFAULT_SECURE = false;

    private String path = DEFAULT_PATH;
    private int maxAge = DEFAULT_MAX_AGE;
    private boolean secure = DEFAULT_SECURE;

    public CookieAttribute() {
    }

    /**
     * Constructs a <tt>CookieAttribute</tt> using a {@link Cookie Cookie} with the specified {@link Cookie#getName() name}
     * using the request context's path and with a {@link Cookie#setMaxAge(int) maxAge} of <tt>-1</tt>, indicating the
     * Cookie will persist until browser shutdown.
     *
     * @param name the Cookie {@link Cookie#getName() name}
     */
    public CookieAttribute(String name) {
        super(name);
    }

    /**
     * Constructs a <tt>CookieAttribute</tt> using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name} and {@link Cookie#getPath() path}.
     *
     * <p>A <tt>null</tt> <tt>path</tt> value means the request context's path will be used by default.
     *
     * <p>The Cookie's {@link Cookie#getMaxAge() maxAge} will be <tt>-1</tt>, indicating the Cookie will persist until
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
     * Constructs a <tt>CookieAttribute</tt> using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name} and {@link Cookie#getMaxAge() maxAge}.
     *
     * <p>The Cookie's {@link javax.servlet.http.Cookie#getPath() path} will be the <tt>Request</tt>'s
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
     * Constructs a <tt>CookieAttribute</tt> using a {@link Cookie Cookie} with the specified
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
     * Constructs a <tt>CookieAttribute</tt> using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name}, {@link javax.servlet.http.Cookie#getPath() path}, and
     * {@link Cookie#getMaxAge() maxAge}, utilizing the specified <tt>PropertyEditor</tt> to perform value/string
     * conversion on the object stored as a cookie.
     *
     * @param name        the Cookie {@link Cookie#getName() name}
     * @param path        the Cookie {@link Cookie#setPath(String) path}.
     * @param maxAge      the Cookie {@link Cookie#getMaxAge() maxAge}
     * @param editorClass the <tt>PropertyEditor</tt> to perform value/string conversion on the object stored as a
     *                    Cookie.
     */
    public CookieAttribute(String name, String path, int maxAge, Class<? extends PropertyEditor> editorClass) {
        super(name, editorClass);
        setPath(path);
        setMaxAge(maxAge);
    }

    /**
     * Returns the Cookie's {@link Cookie#getPath() path} setting.  If <tt>null</tt>, the <tt>request</tt>'s
     * {@link javax.servlet.http.HttpServletRequest#getContextPath() context path} will be used.
     *
     * <p>The default is <code>null</code>.</p>
     *
     * @return the Cookie's path, or <tt>null</tt> if the request's context path should be used as the path when the
     *         cookie is created.
     */
    public String getPath() {
        return path;
    }

    /**
     * Sets the Cookie's {@link Cookie#getPath() path} setting.  If the argument is <tt>null</tt>, the <tt>request</tt>'s
     * {@link javax.servlet.http.HttpServletRequest#getContextPath() context path} will be used.
     *
     * <p>The default is <code>null</code>.</p>
     *
     * @param path the Cookie's path, or <tt>null</tt> if the request's context path should be used as the path when the
     *             cookie is created.
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     * Returns the Cookie's {@link Cookie#setMaxAge(int) maxAge} setting.  Please see that JavaDoc for the semantics on
     * the repercussions of negative, zero, and positive values for the maxAge.
     *
     * <p>The default value is <code>-1</code>, meaning the cookie will expire when the browser is closed.</p>
     *
     * @return the Cookie's {@link Cookie#setMaxAge(int) maxAge}
     */
    public int getMaxAge() {
        return maxAge;
    }

    /**
     * Sets the Cookie's {@link Cookie#setMaxAge(int) maxAge} setting.  Please see that JavaDoc for the semantics on
     * the repercussions of negative, zero, and positive values for the maxAge.
     *
     * <p>The default value is <code>-1</code>, meaning the cookie will expire when the browser is closed.</p>
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

    /**
     * Returns the cookie with the given name from the request or <tt>null</tt> if no cookie
     * with that name could be found.
     *
     * @param request    the current executing http request.
     * @param cookieName the name of the cookie to find and return.
     * @return the cookie with the given name from the request or <tt>null</tt> if no cookie
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

        String stringValue;
        Cookie cookie = getCookie(toHttp(request), getName());
        if (cookie != null && cookie.getMaxAge() != 0 ) {
            stringValue = cookie.getValue();
            if (log.isInfoEnabled()) {
                log.info("Found string value [" + stringValue + "] from HttpServletRequest Cookie [" + getName() + "]");
            }
            value = fromStringValue(stringValue);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No value found in request Cookies under cookie name [" + getName() + "]");
            }
        }

        return value;
    }

    public void onStoreValue(T value, ServletRequest servletRequest, ServletResponse servletResponse) {

        HttpServletRequest request = toHttp(servletRequest);
        HttpServletResponse response = toHttp(servletResponse);

        String name = getName();
        int maxAge = getMaxAge();
        String path = getPath() != null ? getPath() : request.getContextPath();

        String stringValue = toStringValue(value);
        Cookie cookie = new Cookie(name, stringValue);
        cookie.setMaxAge(maxAge);
        cookie.setPath(path);
        if (isSecure()) {
            cookie.setSecure(true);
        }

        response.addCookie(cookie);
        if (log.isTraceEnabled()) {
            log.trace("Added Cookie [" + name + "] to path [" + path + "] with value [" +
                    stringValue + "] to the HttpServletResponse.");
        }
    }

    public void removeValue(ServletRequest servletRequest, ServletResponse response) {
        HttpServletRequest request = toHttp(servletRequest);
        Cookie cookie = getCookie(request, getName());
        if (cookie != null) {
            cookie.setMaxAge(0);
            //JSEC-94: Must set the path on the outgoing cookie (some browsers don't retain it from the
            //retrieved cookie?)
            cookie.setPath(getPath() == null ? request.getContextPath() : getPath());
            cookie.setSecure(isSecure());
            toHttp(response).addCookie(cookie);
        }
    }
}
