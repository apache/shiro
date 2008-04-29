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
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.attr.CookieAttribute;
import org.jsecurity.web.attr.WebAttribute;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class WebRememberMeManager extends AbstractRememberMeManager {

    public static final String DEFAULT_REMEMBER_ME_COOKIE_NAME = "rememberMe";

    protected WebAttribute<String> identityAttribute = null;

    public WebRememberMeManager() {
        super();
        CookieAttribute<String> attr = new CookieAttribute<String>(DEFAULT_REMEMBER_ME_COOKIE_NAME);
        attr.setCheckRequestParams(false);
        attr.setMaxAge(CookieAttribute.INDEFINITE);
        this.identityAttribute = attr;
    }

    public WebAttribute<String> getIdentityAttribute() {
        return identityAttribute;
    }

    public void setIdentityAttribute(WebAttribute<String> identityAttribute) {
        this.identityAttribute = identityAttribute;
    }

    protected void rememberSerializedIdentity(byte[] serialized) {
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        //base 64 encode it and store as a cookie:
        String base64 = Base64.encodeToString(serialized);
        getIdentityAttribute().storeValue(base64, request, response);
    }

    protected byte[] getSerializedRememberedIdentity() {
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        String base64 = getIdentityAttribute().retrieveValue(request, response);
        if ( base64 != null ) {
            return Base64.decode( base64 );
        } else {
            //no cookie set - new site visitor?
            return null;
        }
    }

    protected void forgetIdentity() {
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        getIdentityAttribute().removeValue( request, response );
    }
}
