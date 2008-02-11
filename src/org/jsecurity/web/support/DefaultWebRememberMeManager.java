/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.web.support;

import org.jsecurity.codec.Base64;
import org.jsecurity.context.support.AbstractRememberMeManager;
import org.jsecurity.util.ThreadContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * @author Les Hazlewood
 * @since 1.0
 */
public class DefaultWebRememberMeManager extends AbstractRememberMeManager {

    public static final String DEFAULT_REMEMBER_ME_COOKIE_NAME = "rememberMe";

    protected CookieStore<String> cookieStore = null;

    public CookieStore<String> getCookieStore() {
        return cookieStore;
    }

    public void setCookieStore(CookieStore<String> cookieStore) {
        this.cookieStore = cookieStore;
    }

    protected void onInit() {
        ensureCookieStore();
    }

    protected void ensureCookieStore() {
        CookieStore<String> cookieStore = getCookieStore();
        if (cookieStore == null) {
            cookieStore = new CookieStore<String>(DEFAULT_REMEMBER_ME_COOKIE_NAME);
            cookieStore.setCheckRequestParams(false);
            setCookieStore(cookieStore);
        }
    }

    protected void rememberSerializedIdentity(byte[] serialized) {
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();

        //base 64 encode it and store as a cookie:
        String base64 = Base64.encodeBase64ToString(serialized);

        getCookieStore().storeValue(base64, request, response);
    }

    protected byte[] getRememberedSerializedIdentity() {
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();

        String base64 = getCookieStore().retrieveValue(request, response);

        return Base64.decodeBase64(base64);
    }
}
