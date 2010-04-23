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

import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.web.WebUtils;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.WebSubjectContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Remembers a Subject's identity by saving the Subject's {@link Subject#getPrincipals() principals} to a {@link Cookie}
 * for later retrieval.
 * <p/>
 * Cookie attributes (path, domain, maxAge, etc) may be set on this class's default
 * {@link #getCookie() cookie} attribute.  The cookie's default name is {@code rememberMe}.
 * <p/>
 * Note that because this class subclasses the {@link AbstractRememberMeManager} which already provides serialization
 * and encryption logic, this class utilizes both for added security before setting the cookie value.
 *
 * @author Les Hazlewood
 * @author Luis Arias
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

    public CookieRememberMeManager() {
        Cookie cookie = new SimpleCookie(DEFAULT_REMEMBER_ME_COOKIE_NAME);
        cookie.setPath(Cookie.ROOT_PATH);
        //Peter (Apache Shiro developer) said that Jetty didn't like the CookieAttribute.INDEFINITE value
        // (Tomcat was ok with it), so just default to a few years for now.  If anyone doesn't visit a site in 3 years
        // after last login, I doubt any Shiro users would mind their end-users to be forced to log in. - LAH.
        cookie.setMaxAge(Cookie.ONE_YEAR * 3);
        this.cookie = cookie;
    }

    public Cookie getCookie() {
        return cookie;
    }

    public void setCookie(Cookie cookie) {
        this.cookie = cookie;
    }

    protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
        WebSubject webSubject = (WebSubject) subject;
        ServletRequest servletRequest = webSubject.getServletRequest();
        ServletResponse servletResponse = webSubject.getServletResponse();
        HttpServletRequest request = WebUtils.toHttp(servletRequest);
        HttpServletResponse response = WebUtils.toHttp(servletResponse);

        //base 64 encode it and store as a cookie:
        String base64 = Base64.encodeToString(serialized);

        Cookie template = getCookie(); //the class attribute is really a template for the outgoing cookies
        Cookie cookie = new SimpleCookie(template);
        cookie.setValue(base64);
        cookie.saveTo(request, response);
    }

    private ServletRequest getServletRequest(SubjectContext subjectContext) {
        ServletRequest request = null;
        if (subjectContext != null && subjectContext instanceof WebSubjectContext) {
            request = ((WebSubjectContext) subjectContext).getServletRequest();
        }
        return request;
    }

    private ServletResponse getServletResponse(SubjectContext subjectContext) {
        ServletResponse response = null;
        if (subjectContext != null && subjectContext instanceof WebSubjectContext) {
            response = ((WebSubjectContext) subjectContext).getServletResponse();
        }
        return response;
    }

    protected boolean isIdentityRemoved(SubjectContext subjectContext) {
        ServletRequest request = getServletRequest(subjectContext);
        if (request != null) {
            Boolean removed = (Boolean) request.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY);
            return removed != null && removed;
        }
        return false;
    }

    protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {

        if (CollectionUtils.isEmpty(subjectContext)) {
            if (log.isTraceEnabled()) {
                log.trace("Null or empty SubjectContext - unable to retrieve request/response pair to obtain " +
                        "a request-based identity.  Returning null.");
            }
            return null;
        }

        if (isIdentityRemoved(subjectContext)) {
            return null;
        }

        ServletRequest servletRequest = getServletRequest(subjectContext);
        ServletResponse servletResponse = getServletResponse(subjectContext);
        HttpServletRequest request = WebUtils.toHttp(servletRequest);
        HttpServletResponse response = WebUtils.toHttp(servletResponse);

        String base64 = getCookie().readValue(request, response);

        if (base64 != null) {
            base64 = ensurePadding(base64);
            if (log.isTraceEnabled()) {
                log.trace("Acquired Base64 encoded identity [" + base64 + "]");
            }
            byte[] decoded = Base64.decode(base64);
            if (log.isTraceEnabled()) {
                log.trace("Base64 decoded byte array length: " + (decoded != null ? decoded.length : 0) + " bytes.");
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
            StringBuffer sb = new StringBuffer(base64);
            for (int i = 0; i < length % 4; ++i) {
                sb.append('=');
            }
            base64 = sb.toString();
        }
        return base64;
    }

    protected void forgetIdentity(Subject subject) {
        WebSubject webSubject = (WebSubject) subject;
        ServletRequest request = webSubject.getServletRequest();
        ServletResponse response = webSubject.getServletResponse();
        forgetIdentity(request, response);
    }

    protected void forgetIdentity(SubjectContext subjectContext) {
        ServletRequest request = getServletRequest(subjectContext);
        ServletResponse response = getServletResponse(subjectContext);
        forgetIdentity(request, response);
    }

    protected void forgetIdentity(ServletRequest request, ServletResponse response) {
        getCookie().removeFrom(WebUtils.toHttp(request), WebUtils.toHttp(response));
    }
}

