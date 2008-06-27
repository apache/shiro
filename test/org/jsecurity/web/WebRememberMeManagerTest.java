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
package org.jsecurity.web;

import static org.easymock.EasyMock.*;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.SimpleAccount;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.SimplePrincipalCollection;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
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
        ServletRequest mockRequest = createMock(HttpServletRequest.class);
        WebUtils.bind(mockRequest);
        ServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebUtils.bind(mockResponse);

        WebRememberMeManager mgr = new WebRememberMeManager();
        UsernamePasswordToken token = new UsernamePasswordToken("user", "secret");
        token.setRememberMe(true);
        Account account = new SimpleAccount("user", "secret", "test");

        mgr.onSuccessfulLogin(token, account);
    }

    @Test
    public void getRememberedPrincipals() {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        WebUtils.bind(mockRequest);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebUtils.bind(mockResponse);

        //The following base64 string was determined from the log output of the above test.
        //This may have to change if the VM changes - not sure. L.H.
        final String userPCBlowfishBase64 = "clJgEjFZVuRRN5lCpInkOsawSaKK4hLwegZK/QgR1Thk380v5wL9pA1NZo7QHr7eg8BYryoQaGq0KkrLytelnsl1lierxE9EJ1typI2GpgMeG+HmceNdrlN6KGh4AmjLG3zCUPo8E+QzGVs/EO3PIAGyYYtuYbW++oJDr5xfY9DwK4Omq5GijZSSmdpOHiYelPMa1XLwT0D/kNCUm6EVfG6TKwxViNtGdyzknY7abNU7ucw2UWfjFe24hH0SL0hZMXjPQYtMnPl5J5qfjU4EXX1a/Ijn0IKUEk5BmY+ipc6irMI/Rrmumr46XAIU3uwWMxlbPxDtzyABsmGLbmG1vvqCQ6+cX2PQJ37oNcKqr4mV7ObN2EvWZ1uVbJlUdXeEQgghL3/ayatTs3hWwFGdNhgef8c8iX9wM5bEvxqqY9TMXEyLYLZeA8H6gNvJc6hRd0TQFkzUhjs=";
        Cookie[] cookies = new Cookie[]{
                new Cookie(WebRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCBlowfishBase64)
        };

        expect(mockRequest.getCookies()).andReturn(cookies);
        replay(mockRequest);

        WebRememberMeManager mgr = new WebRememberMeManager();
        PrincipalCollection collection = mgr.getRememberedPrincipals();

        verify(mockRequest);

        assertTrue(collection != null);
        assertTrue(collection.iterator().next().equals("user"));
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

        PrincipalCollection pc = new SimplePrincipalCollection("test", "user");
        WebRememberMeManager mgr = new WebRememberMeManager();
        mgr.onLogout(pc);

        verify(mockRequest);
        verify(mockResponse);
    }

}
