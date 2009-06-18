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
package org.apache.shiro.web;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.web.attr.CookieAttribute;
import org.apache.shiro.web.attr.WebAttribute;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Remembers a Subject's identity by using a {@link WebAttribute WebAttribute} instance to retain
 * the identity value between web requests.
 * <p/>
 * This class's default <code>WebAttribute</code> instance is a {@link org.apache.shiro.web.attr.CookieAttribute CookieAttribute}, storing
 * the Subject's {@link org.apache.shiro.subject.Subject#getPrincipals principals} in a <code>Cookie</code>.  Note that
 * because this class subclasses the <code>AbstractRememberMeManager</code> which already provides serialization and
 * encryption logic, this class utilizes both for added security before setting the cookie value.
 * <p/>
 * This class also contains &quot;passthrough&quot; JavaBeans-compatible getters/setters for the underlying
 * <code>CookieAttribute</code>'s properties to make configuration easier.
 * <p/>
 * Note however as a basic sanity check, these passthrough methods will first assert that the underlying
 * {@link #getIdentityAttribute identityAttribute} is actually a {@link CookieAttribute CookieAttribute}.  If it
 * is not, an {@link IllegalStateException} will be thrown.  Because the default instance of this class <em>is</em>
 * already <code>CookieAttribute</code>, you would only ever experience the exception if you explicitly
 * override the internal instance with a different type and accidentally call one of these JavaBeans passthrough
 * methods.
 * <p/>
 * Just be aware of this if you manually override the {@link #getIdentityAttribute identityAttribute} property
 * to be an instance of something <em>other</em> than a <code>CookieAttribute</code>.
 *
 * @author Les Hazlewood
 * @author Luis Arias
 * @since 0.9
 */
public class WebRememberMeManager extends AbstractRememberMeManager {

    //TODO - complete JavaDoc

    private static transient final Logger log = LoggerFactory.getLogger(WebRememberMeManager.class);

    /**
     * The default name of the underlying rememberMe cookie which is <code>rememberMe</code>.
     */
    public static final String DEFAULT_REMEMBER_ME_COOKIE_NAME = "rememberMe";

    protected WebAttribute<String> identityAttribute = null;

    public WebRememberMeManager() {
        CookieAttribute<String> attr = new CookieAttribute<String>(DEFAULT_REMEMBER_ME_COOKIE_NAME);
        attr.setCheckRequestParams(false);
        //Peter (Apache Shiro developer) said that Jetty didn't like the CookieAttribute.INDEFINITE value
        // (Tomcat was ok with it), so just default to a few years for now.  If anyone doesn't visit a site in 3 years
        // after last login, I doubt any Shiro users would mind their end-users to be forced to log in. - LAH.
        attr.setMaxAge(CookieAttribute.ONE_YEAR * 3);
        this.identityAttribute = attr;
    }

    public WebAttribute<String> getIdentityAttribute() {
        return identityAttribute;
    }

    public void setIdentityAttribute(WebAttribute<String> identityAttribute) {
        this.identityAttribute = identityAttribute;
    }

    protected CookieAttribute getCookieAttribute() {
        assertCookieAttribute();
        return (CookieAttribute) getIdentityAttribute();
    }

    protected void assertCookieAttribute() {
        if (!(this.identityAttribute instanceof CookieAttribute)) {
            String msg = "Attempting to access a Cookie property, but the underlying " +
                    WebAttribute.class.getName() + " instance is not a " +
                    CookieAttribute.class.getName() + " instance.  This is expected if you " +
                    "are accessing or modifying a cookie property.";
            throw new IllegalStateException(msg);
        }
    }

    /**
     * Passthrough JavaBeans property that will get the underyling rememberMe cookie's name.
     * <p/>
     * The default value is {@link #DEFAULT_REMEMBER_ME_COOKIE_NAME}
     * <p/>
     * This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.
     *
     * @return the underlying rememberMe cookie's name
     */
    public String getCookieName() {
        return getCookieAttribute().getName();
    }

    /**
     * Passthrough JavaBeans property that will set the underyling rememberMe cookie's name.
     * <p/>
     * The default value is {@link #DEFAULT_REMEMBER_ME_COOKIE_NAME}
     * <p/>
     * This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.
     *
     * @param name the name to assign to the underlying rememberMe cookie
     */
    public void setCookieName(String name) {
        getCookieAttribute().setName(name);
    }

    public String getCookieDomain() {
        return getCookieAttribute().getDomain();
    }

    public void setCookieDomain(String domain) {
        getCookieAttribute().setDomain(domain);
    }

    /**
     * Passthrough JavaBeans property that will get the underyling rememberMe cookie's path.
     * <p/>
     * This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.
     *
     * @return the underlying rememberMe cookie's path
     */
    public String getCookiePath() {
        return getCookieAttribute().getPath();
    }

    /**
     * Passthrough JavaBeans property that will set the underyling rememberMe cookie's path.
     * <p/>
     * This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.
     *
     * @param path the path to assign to the underlying rememberMe cookie
     */
    public void setCookiePath(String path) {
        getCookieAttribute().setPath(path);
    }

    /**
     * Passthrough JavaBeans property that will get the underyling rememberMe cookie's max age.
     * <p/>
     * This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.
     *
     * @return the underlying rememberMe cookie's max age.
     */
    public int getCookieMaxAge() {
        return getCookieAttribute().getMaxAge();
    }

    /**
     * Passthrough JavaBeans property that will get the underyling rememberMe cookie's max age.
     * <p/>
     * This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.
     *
     * @param maxAge the max age to assign to the underlying rememberMe cookie
     */
    public void setCookieMaxAge(int maxAge) {
        getCookieAttribute().setMaxAge(maxAge);
    }

    public int getCookieVersion() {
        return getCookieAttribute().getVersion();
    }

    public void setCookieVersion(int version) {
        getCookieAttribute().setVersion(version);
    }

    /**
     * Passthrough JavaBeans property that will get the underyling rememberMe cookie's 'secure' status.
     * <p/>
     * This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.
     *
     * @return the underlying rememberMe cookie's 'secure' flag
     */
    public boolean isCookieSecure() {
        return getCookieAttribute().isSecure();
    }

    /**
     * Passthrough JavaBeans property that will set the underyling rememberMe cookie's 'secure' status.
     * <p/>
     * This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.
     *
     * @param secure the 'secure' flag to assign to the underlying rememberMe cookie.
     */
    public void setCookieSecure(boolean secure) {
        getCookieAttribute().setSecure(secure);
    }

    public String getCookieComment() {
        return getCookieAttribute().getComment();
    }

    public void setCookieComment(String comment) {
        getCookieAttribute().setComment(comment);
    }

    protected void rememberSerializedIdentity(byte[] serialized) {
        ServletRequest request = WebUtils.getRequiredServletRequest();
        ServletResponse response = WebUtils.getRequiredServletResponse();
        //base 64 encode it and store as a cookie:
        String base64 = Base64.encodeToString(serialized);
        getIdentityAttribute().storeValue(base64, request, response);
    }

    protected boolean isIdentityRemoved() {
        ServletRequest request = WebUtils.getServletRequest();
        if (request != null) {
            Boolean removed = (Boolean) request.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY);
            return removed != null && removed;
        }
        return false;
    }

    protected byte[] getSerializedRememberedIdentity() {
        if (isIdentityRemoved()) {
            return null;
        }

        ServletRequest request = WebUtils.getRequiredServletRequest();
        ServletResponse response = WebUtils.getRequiredServletResponse();
        String base64 = getIdentityAttribute().retrieveValue(request, response);
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


    protected void forgetIdentity() {
        ServletRequest request = WebUtils.getRequiredServletRequest();
        ServletResponse response = WebUtils.getRequiredServletResponse();
        getIdentityAttribute().removeValue(request, response);
    }
}
