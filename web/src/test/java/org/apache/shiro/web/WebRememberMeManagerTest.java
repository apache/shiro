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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * TODO - class javadoc
 *
 * @author Les Hazlewood
 * @since Apr 23, 2008 9:16:47 AM
 */
public class WebRememberMeManagerTest {

    @Test
    public void onSuccessfulLogin() {
        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        WebUtils.bind(mockRequest);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);
        WebUtils.bind(mockResponse);

        WebRememberMeManager mgr = new WebRememberMeManager();
        UsernamePasswordToken token = new UsernamePasswordToken("user", "secret");
        token.setRememberMe(true);
        AuthenticationInfo account = new SimpleAuthenticationInfo("user", "secret", "test");

        expect(mockRequest.getCookies()).andReturn(null);
        expect(mockRequest.getContextPath()).andReturn("/");

        replay(mockRequest);
        mgr.onSuccessfulLogin(token, account);
        verify(mockRequest);
    }

    // SHIRO-69
    @Test
    public void getRememberedPrincipals() {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        WebUtils.bind(mockRequest);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebUtils.bind(mockResponse);

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);

        //The following base64 string was determined from the log output of the above test.
        //This may have to change if the VM changes - not sure. L.H.
        final String userPCBlowfishBase64 = "UwP13UzjVUceLBNWh+sYM01JWOSbBOwc1ZLySIws0IdnkcWeD/yWeH0eIycwHaI8MRKPyenBr76TL6F3P3FpTceMcJ+xDfwSqOgU/ZQLdvIOxlZxmT9RlUvKT6zopnQrSpdsCNaruG/Op/XEoJcdNLI9rJCCyMKN3em5wl8GrWTIzKS4hzHombGBEW4EPS9jv40HV4mIS2sUFXm5MlOptr99e1A6eKYxlLrldk2/yqw29nWohE0sIjO7tRF9mOAZUeC/Fem6K4S82LbXAJ6p0oNg3MP7dbFSkeeDF2CwFJvvi5xVrGyF0RnTzjwKZdTcvg4bx9ifQpKyPayQgsjCjd3pucJfBq1kuw/IyiPdSREnzWAEXOQi9o9II4jNvOJik+VI3QkwWdBBekzEKCACn8uvjlLKSiR8tCs9vbycs5N0FrODxMQ5FDvhV+rZLHtP/KP1puAwmeo=";
        Cookie[] cookies = new Cookie[]{
                new Cookie(WebRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCBlowfishBase64)
        };

        expect(mockRequest.getCookies()).andReturn(cookies);
        replay(mockRequest);

        WebRememberMeManager mgr = new WebRememberMeManager();
        PrincipalCollection collection = mgr.getRememberedPrincipals();

        verify(mockRequest);

        assertTrue(collection != null);
        //noinspection ConstantConditions
        assertTrue(collection.iterator().next().equals("user"));
    }

    // SHIRO-69
    @Test
    public void getRememberedPrincipalsDecryptionError() {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        WebUtils.bind(mockRequest);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebUtils.bind(mockResponse);

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);

        // Simulate a bad return value here (for example if this was encrypted with a different key
        final String userPCBlowfishBase64 = "DlJgEjFZVuRRN5lCpInkOsawSaKK4hLwegZK/QgR1Thk380v5wL9pA1NZo7QHr7erlnry1vt2AqIyM8Fj2HBCsl1lierxE9EJ1typI2GpgMeG+HmceNdrlN6KGh4AmjLG3zCUPo8E+QzGVs/EO3PIAGyYYtuYbW++oJDr5xfY9DwK4Omq5GijZSSmdpOHiYelPMa1XLwT0D/kNCUm6EVfG6TKwxViNtGdyzknY7abNU7ucw2UWfjFe24hH0SL0hZMXjPQYtMnPl5J5qfjU4EXX1a/Ijn0IKUEk5BmY+ipc6irMI/Rrmumr46XAIU3uwWMxlbPxDtzyABsmGLbmG1vvqCQ6+cX2PQJ37oNcKqr4mV7ObN2EvWZ1uVbJlUdXeEQgghL3/ayatTs3hWwFGdNhgef8c8iX9wM5bEvxqqY9TMXEyLYLZeA8H6gNvJc6hRd0TQFkzUhjs=";
        Cookie[] cookies = new Cookie[]{
                new Cookie(WebRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCBlowfishBase64)
        };

        expect(mockRequest.getCookies()).andReturn(cookies);
        replay(mockRequest);

        WebRememberMeManager mgr = new WebRememberMeManager();
        PrincipalCollection collection = mgr.getRememberedPrincipals();

        verify(mockRequest);

        // Collection should be null since there was an error decrypting it
        assertTrue(collection == null);
    }

    @Test
    public void onLogout() {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        WebUtils.bind(mockRequest);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebUtils.bind(mockResponse);

        Cookie cookie = new Cookie(WebRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, "");
        cookie.setMaxAge(0);
        Cookie[] cookies = new Cookie[]{cookie};

        expect(mockRequest.getCookies()).andReturn(cookies);
        expect(mockRequest.getContextPath()).andReturn(null).anyTimes();
        mockResponse.addCookie(eq(cookie));

        replay(mockRequest);
        replay(mockResponse);

        PrincipalCollection pc = new SimplePrincipalCollection("user", "test");
        WebRememberMeManager mgr = new WebRememberMeManager();
        mgr.onLogout(pc);

        verify(mockRequest);
        verify(mockResponse);
    }

}
