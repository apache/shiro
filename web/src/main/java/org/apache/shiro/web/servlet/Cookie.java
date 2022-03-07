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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Interface representing HTTP cookie operations, supporting pojo-style getters and setters for all
 * attributes which includes <a href="http://www.owasp.org/index.php/HttpOnly">HttpOnly</a> support.
 * This allows Shiro to set <a href="http://www.owasp.org/index.php/HttpOnly">HttpOnly</a> cookies even on
 * Servlet containers based on the {@code 2.4} and {@code 2.5} API (Servlet API 'native' support was only introduced in
 * the {@code 2.6} specification).
 *
 * @since 1.0
 */
public interface Cookie {
    /**
     * The value of deleted cookie (with the maxAge 0).
     */
    public static final String DELETED_COOKIE_VALUE = "deleteMe";


    /**
     * The number of seconds in one year (= 60 * 60 * 24 * 365).
     */
    public static final int ONE_YEAR = 60 * 60 * 24 * 365;

    /**
     * Root path to use when the path hasn't been set and request context root is empty or null.
     */
    public static final String ROOT_PATH = "/";

    /**
     * The SameSite attribute of the Set-Cookie HTTP response header allows you to declare if your cookie should be restricted to a first-party or same-site context.
     */
    public enum SameSiteOptions {
        /**
         * Cookies will be sent in all contexts, i.e sending cross-origin is allowed.
         *
         * <p>None used to be the default value, but recent browser versions made Lax the default value
         * to have reasonably robust defense against some classes of cross-site request forgery (CSRF) attacks.</p>
         *
         * <p>None requires the Secure attribute in latest browser versions. See below for more information.</p>
         */
        NONE,
        /**
         * Cookies are allowed to be sent with top-level navigations and will be sent along with GET requests
         * initiated by third party website. This is the default value in modern browsers as of 2020.
         */
        LAX,
        /**
         * Cookies will only be sent in a first-party context
         * and not be sent along with requests initiated by third party websites.
         */
        STRICT,
    }

    String getName();

    void setName(String name);

    String getValue();

    void setValue(String value);

    String getComment();

    void setComment(String comment);

    String getDomain();

    void setDomain(String domain);

    int getMaxAge();

    void setMaxAge(int maxAge);

    String getPath();

    void setPath(String path);

    boolean isSecure();

    void setSecure(boolean secure);

    int getVersion();

    void setVersion(int version);

    void setHttpOnly(boolean httpOnly);

    boolean isHttpOnly();

    void setSameSite(SameSiteOptions sameSite);

    SameSiteOptions getSameSite();

    void saveTo(HttpServletRequest request, HttpServletResponse response);

    void removeFrom(HttpServletRequest request, HttpServletResponse response);

    String readValue(HttpServletRequest request, HttpServletResponse response);
}
