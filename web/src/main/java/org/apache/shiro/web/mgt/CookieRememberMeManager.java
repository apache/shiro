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
package org.apache.shiro.web.mgt;

import org.apache.shiro.lang.codec.Base64;
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.WebSubjectContext;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Remembers a Subject's identity by saving the Subject's {@link Subject#getPrincipals() principals} to a {@link Cookie}
 * for later retrieval.
 * <p/>
 * Cookie attributes (path, domain, maxAge, etc) may be set on this class's default
 * {@link #getCookie() cookie} attribute, which acts as a template to use to set all properties of outgoing cookies
 * created by this implementation.
 * <p/>
 * The default cookie has the following attribute values set:
 * <table>
 * <tr>
 * <th>Attribute Name</th>
 * <th>Value</th>
 * </tr>
 * <tr><td>{@link Cookie#getName() name}</td>
 * <td>{@code rememberMe}</td>
 * </tr>
 * <tr>
 * <td>{@link Cookie#getPath() path}</td>
 * <td>{@code /}</td>
 * </tr>
 * <tr>
 * <td>{@link Cookie#getMaxAge() maxAge}</td>
 * <td>{@link Cookie#ONE_YEAR Cookie.ONE_YEAR}</td>
 * </tr>
 * </table>
 * <p/>
 * Note that because this class subclasses the {@link AbstractRememberMeManager} which already provides serialization
 * and encryption logic, this class utilizes both for added security before setting the cookie value.
 *
 * @since 1.0
 */
public class CookieRememberMeManager extends AbstractRememberMeManager {

    //TODO - complete JavaDoc

    private static transient final Logger log = LoggerFactory.getLogger(CookieRememberMeManager.class);

    /**
     * The default name of the underlying rememberMe cookie which is {@code rememberMe}.
     */
    public static final String DEFAULT_REMEMBER_ME_COOKIE_NAME = "rememberMe";

    private Cookie cookie;

    /**
     * Constructs a new {@code CookieRememberMeManager} with a default {@code rememberMe} cookie template.
     */
    public CookieRememberMeManager() {
        Cookie cookie = new SimpleCookie(DEFAULT_REMEMBER_ME_COOKIE_NAME);
        cookie.setHttpOnly(true);
        //One year should be long enough - most sites won't object to requiring a user to log in if they haven't visited
        //in a year:
        cookie.setMaxAge(Cookie.ONE_YEAR);
        this.cookie = cookie;
    }

    /**
     * Returns the cookie 'template' that will be used to set all attributes of outgoing rememberMe cookies created by
     * this {@code RememberMeManager}.  Outgoing cookies will match this one except for the
     * {@link Cookie#getValue() value} attribute, which is necessarily set dynamically at runtime.
     * <p/>
     * Please see the class-level JavaDoc for the default cookie's attribute values.
     *
     * @return the cookie 'template' that will be used to set all attributes of outgoing rememberMe cookies created by
     *         this {@code RememberMeManager}.
     */
    public Cookie getCookie() {
        return cookie;
    }

    /**
     * Sets the cookie 'template' that will be used to set all attributes of outgoing rememberMe cookies created by
     * this {@code RememberMeManager}.  Outgoing cookies will match this one except for the
     * {@link Cookie#getValue() value} attribute, which is necessarily set dynamically at runtime.
     * <p/>
     * Please see the class-level JavaDoc for the default cookie's attribute values.
     *
     * @param cookie the cookie 'template' that will be used to set all attributes of outgoing rememberMe cookies created
     *               by this {@code RememberMeManager}.
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public void setCookie(Cookie cookie) {
        this.cookie = cookie;
    }

    /**
     * Base64-encodes the specified serialized byte array and sets that base64-encoded String as the cookie value.
     * <p/>
     * The {@code subject} instance is expected to be a {@link WebSubject} instance with an HTTP Request/Response pair
     * so an HTTP cookie can be set on the outgoing response.  If it is not a {@code WebSubject} or that
     * {@code WebSubject} does not have an HTTP Request/Response pair, this implementation does nothing.
     *
     * @param subject    the Subject for which the identity is being serialized.
     * @param serialized the serialized bytes to be persisted.
     */
    protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {

        if (!WebUtils.isHttp(subject)) {
            if (log.isDebugEnabled()) {
                String msg = "Subject argument is not an HTTP-aware instance.  This is required to obtain a servlet " +
                        "request and response in order to set the rememberMe cookie. Returning immediately and " +
                        "ignoring rememberMe operation.";
                log.debug(msg);
            }
            return;
        }


        HttpServletRequest request = WebUtils.getHttpRequest(subject);
        HttpServletResponse response = WebUtils.getHttpResponse(subject);

        //base 64 encode it and store as a cookie:
        String base64 = Base64.encodeToString(serialized);

        Cookie template = getCookie(); //the class attribute is really a template for the outgoing cookies
        Cookie cookie = new SimpleCookie(template);
        cookie.setValue(base64);
        cookie.saveTo(request, response);
    }

    private boolean isIdentityRemoved(WebSubjectContext subjectContext) {
        ServletRequest request = subjectContext.resolveServletRequest();
        if (request != null) {
            Boolean removed = (Boolean) request.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY);
            return removed != null && removed;
        }
        return false;
    }


    /**
     * Returns a previously serialized identity byte array or {@code null} if the byte array could not be acquired.
     * This implementation retrieves an HTTP cookie, Base64-decodes the cookie value, and returns the resulting byte
     * array.
     * <p/>
     * The {@code SubjectContext} instance is expected to be a {@link WebSubjectContext} instance with an HTTP
     * Request/Response pair so an HTTP cookie can be retrieved from the incoming request.  If it is not a
     * {@code WebSubjectContext} or that {@code WebSubjectContext} does not have an HTTP Request/Response pair, this
     * implementation returns {@code null}.
     *
     * @param subjectContext the contextual data, usually provided by a {@link Subject.Builder} implementation, that
     *                       is being used to construct a {@link Subject} instance.  To be used to assist with data
     *                       lookup.
     * @return a previously serialized identity byte array or {@code null} if the byte array could not be acquired.
     */
    protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {

        if (!WebUtils.isHttp(subjectContext)) {
            if (log.isDebugEnabled()) {
                String msg = "SubjectContext argument is not an HTTP-aware instance.  This is required to obtain a " +
                        "servlet request and response in order to retrieve the rememberMe cookie. Returning " +
                        "immediately and ignoring rememberMe operation.";
                log.debug(msg);
            }
            return null;
        }

        WebSubjectContext wsc = (WebSubjectContext) subjectContext;
        if (isIdentityRemoved(wsc)) {
            return null;
        }

        HttpServletRequest request = WebUtils.getHttpRequest(wsc);
        HttpServletResponse response = WebUtils.getHttpResponse(wsc);

        String base64 = getCookie().readValue(request, response);
        // Browsers do not always remove cookies immediately (SHIRO-183)
        // ignore cookies that are scheduled for removal
        if (Cookie.DELETED_COOKIE_VALUE.equals(base64)) return null;

        if (base64 != null) {
            base64 = ensurePadding(base64);
            if (log.isTraceEnabled()) {
                log.trace("Acquired Base64 encoded identity [" + base64 + "]");
            }
            byte[] decoded;
            try {
                decoded = Base64.decode(base64);
            } catch (RuntimeException rtEx) {
                /*
                 * https://issues.apache.org/jira/browse/SHIRO-766:
                 * If the base64 string cannot be decoded, just assume there is no valid cookie value.
                 * */
                getCookie().removeFrom(request, response);
                log.warn("Unable to decode existing base64 encoded entity: [" + base64 + "].", rtEx);
                return null;
            }

            if (log.isTraceEnabled()) {
                log.trace("Base64 decoded byte array length: " + decoded.length + " bytes.");
            }
            return decoded;
        } else {
            //no cookie set - new site visitor?
            return null;
        }
    }

    /**
     * Sometimes a user agent will send the rememberMe cookie value without padding,
     * most likely because {@code =} is a separator in the cookie header.
     * <p/>
     * Contributed by Luis Arias.  Thanks Luis!
     *
     * @param base64 the base64 encoded String that may need to be padded
     * @return the base64 String padded if necessary.
     */
    private String ensurePadding(String base64) {
        int length = base64.length();
        if (length % 4 != 0) {
            StringBuilder sb = new StringBuilder(base64);
            for (int i = 0; i < length % 4; ++i) {
                sb.append('=');
            }
            base64 = sb.toString();
        }
        return base64;
    }

    /**
     * Removes the 'rememberMe' cookie from the associated {@link WebSubject}'s request/response pair.
     * <p/>
     * The {@code subject} instance is expected to be a {@link WebSubject} instance with an HTTP Request/Response pair.
     * If it is not a {@code WebSubject} or that {@code WebSubject} does not have an HTTP Request/Response pair, this
     * implementation does nothing.
     *
     * @param subject the subject instance for which identity data should be forgotten from the underlying persistence
     */
    protected void forgetIdentity(Subject subject) {
        if (WebUtils.isHttp(subject)) {
            HttpServletRequest request = WebUtils.getHttpRequest(subject);
            HttpServletResponse response = WebUtils.getHttpResponse(subject);
            forgetIdentity(request, response);
        }
    }

    /**
     * Removes the 'rememberMe' cookie from the associated {@link WebSubjectContext}'s request/response pair.
     * <p/>
     * The {@code SubjectContext} instance is expected to be a {@link WebSubjectContext} instance with an HTTP
     * Request/Response pair.  If it is not a {@code WebSubjectContext} or that {@code WebSubjectContext} does not
     * have an HTTP Request/Response pair, this implementation does nothing.
     *
     * @param subjectContext the contextual data, usually provided by a {@link Subject.Builder} implementation
     */
    public void forgetIdentity(SubjectContext subjectContext) {
        if (WebUtils.isHttp(subjectContext)) {
            HttpServletRequest request = WebUtils.getHttpRequest(subjectContext);
            HttpServletResponse response = WebUtils.getHttpResponse(subjectContext);
            forgetIdentity(request, response);
        }
    }

    /**
     * Removes the rememberMe cookie from the given request/response pair.
     *
     * @param request  the incoming HTTP servlet request
     * @param response the outgoing HTTP servlet response
     */
    private void forgetIdentity(HttpServletRequest request, HttpServletResponse response) {
        getCookie().removeFrom(request, response);
    }
}

