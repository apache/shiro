/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web;

import org.jsecurity.codec.Base64;
import org.jsecurity.subject.AbstractRememberMeManager;
import org.jsecurity.web.attr.CookieAttribute;
import org.jsecurity.web.attr.WebAttribute;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Remembers a Subject's identity by using a {@link WebAttribute WebAttribute} instance to retain
 * the identity value between web requests.
 *
 * <p>This class's default <code>WebAttribute</code> instance is a {@link CookieAttribute CookieAttribute}, storing
 * the Subject's {@link org.jsecurity.subject.Subject#getPrincipals principals} in a <code>Cookie</code>.  Note that
 * because this class subclasses the <code>AbstractRememberMeManager</code> which already provides serialization and
 * encryption logic, this class utilizes both for added security before setting the cookie value.</p>
 *
 * <p>This class also contains &quot;passthrough&quot; JavaBeans-compatible getters/setters for the underlying
 * <code>CookieAttribute</code>'s properties to make configuration easier.</p>
 *
 * <p>Note however as a basic sanity check, these passthrough methods will first assert that the underlying
 * {@link #getIdentityAttribute identityAttribute} is actually a {@link CookieAttribute CookieAttribute}.  If it
 * is not, an {@link IllegalStateException} will be thrown.  Because the default instance of this class <em>is</em>
 * already <code>CookieAttribute</code>, you would only ever experience the exception if you explicitly
 * override the internal instance with a different type and accidentally call one of these JavaBeans passthrough
 * methods.</p>
 *
 * <p>Just be aware of this if you manually override the {@link #getIdentityAttribute identityAttribute} property
 * to be an instance of something <em>other</em> than a <code>CookieAttribute</code>.</p>
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class WebRememberMeManager extends AbstractRememberMeManager {

    /** The default name of the underlying rememberMe cookie which is <code>rememberMe</code>. */
    public static final String DEFAULT_REMEMBER_ME_COOKIE_NAME = "rememberMe";

    protected WebAttribute<String> identityAttribute = null;

    public WebRememberMeManager() {
        CookieAttribute<String> attr = new CookieAttribute<String>(DEFAULT_REMEMBER_ME_COOKIE_NAME);
        attr.setCheckRequestParams(false);
        //Peter (JSecurity developer) said that Jetty didn't like the CookieAttribute.INDEFINITE value
        // (Tomcat was ok with it), so just default to a few years for now.  If anyone doesn't visit a site in 3 years
        // after last login, I doubt any JSecurity users would mind their end-users to be forced to log in. - LAH.
        attr.setMaxAge(CookieAttribute.ONE_YEAR * 3);
        this.identityAttribute = attr;
    }

    public WebAttribute<String> getIdentityAttribute() {
        return identityAttribute;
    }

    public void setIdentityAttribute(WebAttribute<String> identityAttribute) {
        this.identityAttribute = identityAttribute;
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
     *
     * <p>The default value is {@link #DEFAULT_REMEMBER_ME_COOKIE_NAME}</p>
     *
     * <p>This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.</p>
     *
     * @return the underlying rememberMe cookie's name
     */
    public String getCookieName() {
        assertCookieAttribute();
        return ((CookieAttribute) this.identityAttribute).getName();
    }

    /**
     * Passthrough JavaBeans property that will set the underyling rememberMe cookie's name.
     *
     * <p>The default value is {@link #DEFAULT_REMEMBER_ME_COOKIE_NAME}</p>
     *
     * <p>This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.</p>
     *
     * @param name the name to assign to the underlying rememberMe cookie
     */
    public void setCookieName(String name) {
        assertCookieAttribute();
        ((CookieAttribute) this.identityAttribute).setName(name);
    }

    /**
     * Passthrough JavaBeans property that will get the underyling rememberMe cookie's path.
     *
     * <p>This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.</p>
     *
     * @return the underlying rememberMe cookie's path
     */
    public String getCookiePath() {
        assertCookieAttribute();
        return ((CookieAttribute) this.identityAttribute).getPath();
    }

    /**
     * Passthrough JavaBeans property that will set the underyling rememberMe cookie's path.
     *
     * <p>This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.</p>
     * @param path the path to assign to the underlying rememberMe cookie
     */
    public void setCookiePath(String path) {
        assertCookieAttribute();
        ((CookieAttribute) this.identityAttribute).setPath(path);
    }

    /**
     * Passthrough JavaBeans property that will get the underyling rememberMe cookie's max age.
     *
     * <p>This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.</p>
     *
     * @return the underlying rememberMe cookie's max age.
     */
    public int getCookieMaxAge() {
        assertCookieAttribute();
        return ((CookieAttribute) this.identityAttribute).getMaxAge();
    }

    /**
     * Passthrough JavaBeans property that will get the underyling rememberMe cookie's max age.
     *
     * <p>This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.</p>
     *
     * @param maxAge the max age to assign to the underlying rememberMe cookie
     */
    public void setCookieMaxAge(int maxAge) {
        assertCookieAttribute();
        ((CookieAttribute) this.identityAttribute).setMaxAge(maxAge);
    }

    /**
     * Passthrough JavaBeans property that will get the underyling rememberMe cookie's 'secure' status.
     *
     * <p>This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.</p>
     *
     * @return the underlying rememberMe cookie's 'secure' flag
     */
    public boolean isCookieSecure() {
        assertCookieAttribute();
        return ((CookieAttribute) this.identityAttribute).isSecure();
    }

    /**
     * Passthrough JavaBeans property that will set the underyling rememberMe cookie's 'secure' status.
     *
     * <p>This method performs a quick <code>CookieAttribute</code> sanity check as described in the class-level JavaDoc.</p>
     * 
     * @param secure the 'secure' flag to assign to the underlying rememberMe cookie.
     */
    public void setCookieSecure(boolean secure) {
        assertCookieAttribute();
        ((CookieAttribute) this.identityAttribute).setSecure(secure);
    }

    protected void rememberSerializedIdentity(byte[] serialized) {
        ServletRequest request = WebUtils.getServletRequest();
        ServletResponse response = WebUtils.getServletResponse();
        //base 64 encode it and store as a cookie:
        String base64 = Base64.encodeToString(serialized);
        getIdentityAttribute().storeValue(base64, request, response);
    }

    protected byte[] getSerializedRememberedIdentity() {
        ServletRequest request = WebUtils.getServletRequest();
        ServletResponse response = WebUtils.getServletResponse();
        String base64 = getIdentityAttribute().retrieveValue(request, response);
        if (base64 != null) {
            return Base64.decode(base64);
        } else {
            //no cookie set - new site visitor?
            return null;
        }
    }

    protected void forgetIdentity() {
        ServletRequest request = WebUtils.getServletRequest();
        ServletResponse response = WebUtils.getServletResponse();
        getIdentityAttribute().removeValue(request, response);
    }
}
