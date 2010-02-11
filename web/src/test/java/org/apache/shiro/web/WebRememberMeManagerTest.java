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
import org.apache.shiro.io.SerializationException;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.subject.WebSubject;
import org.junit.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);
        WebSubject mockSubject = createNiceMock(WebSubject.class);
        expect(mockSubject.getServletRequest()).andReturn(mockRequest).anyTimes();
        expect(mockSubject.getServletResponse()).andReturn(mockResponse).anyTimes();

        WebRememberMeManager mgr = new WebRememberMeManager();
        UsernamePasswordToken token = new UsernamePasswordToken("user", "secret");
        token.setRememberMe(true);
        AuthenticationInfo account = new SimpleAuthenticationInfo("user", "secret", "test");

        expect(mockRequest.getCookies()).andReturn(null);
        expect(mockRequest.getContextPath()).andReturn("/");

        replay(mockSubject);
        replay(mockRequest);
        mgr.onSuccessfulLogin(mockSubject, token, account);
        verify(mockRequest);
        verify(mockSubject);
    }

    // SHIRO-69
    @Test
    public void getRememberedPrincipals() {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        Map<String,Object> context = new HashMap<String,Object>();
        context.put(SubjectFactory.SERVLET_REQUEST, mockRequest);
        context.put(SubjectFactory.SERVLET_RESPONSE, mockResponse);

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);

        //The following base64 string was determined from the log output of the above 'onSuccessfulLogin' test.
        //This will have to change any time the PrincipalCollection implementation changes:
        final String userPCBlowfishBase64 = "UwP13UzjVUceLBNWh+sYM01JWOSbBOwc1ZLySIws0Idnkc" +
                "WeD/yWeH0eIycwHaI8MRKPyenBr77dBdt3S7KTKzzt47bdseNbEI7TbTKPY5VfnJLqGVglQr+O" +
                "mTgH1vpCQ/PAw3XnrQ4FWSXe9/KkfcAfteY5iw7qea1zZJq5jC4dOU3HLlhL7+BtlFMOrSzP2i" +
                "ijwEZGFoNASMTpLxTpiiTHhVmB9Hf4s7N2rTthK18+uTyJwC1KoK3Fw82Wxl7BZb5aFoc5BoJb" +
                "lWyZVHV3hEIIIS9/2smrjrCdu0NRC31c/+IelggTG3jTMA1wQ0oq2jTZSjctlcknV90jxNJfbf" +
                "/Uzk679TmgyrHJgRrQ+kqJ+94rafqFWEcaG82yT3LkQEjE6S8U6Yokx4VZgfR3+Nnhgfb36EfU" +
                "BXytFPop+38q1ssgLNxj3TPPOMj/QfGHVX6lM6loW8zA3VIEtDyqXN0LAQzqnbC8zqb1CJhXaJ" +
                "owmdO9LV7XzouBN+l/ER8I";

        Cookie[] cookies = new Cookie[]{
                new Cookie(WebRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCBlowfishBase64)
        };

        expect(mockRequest.getCookies()).andReturn(cookies);
        replay(mockRequest);

        WebRememberMeManager mgr = new WebRememberMeManager();
        PrincipalCollection collection = mgr.getRememberedPrincipals(context);

        verify(mockRequest);

        assertTrue(collection != null);
        //noinspection ConstantConditions
        assertTrue(collection.iterator().next().equals("user"));
    }

    // SHIRO-69
    @Test
    public void getRememberedPrincipalsDecryptionError() {
        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);

        Map<String,Object> context = new HashMap<String,Object>();
        context.put(SubjectFactory.SERVLET_REQUEST, mockRequest);
        context.put(SubjectFactory.SERVLET_RESPONSE, mockResponse);

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);

        // Simulate a bad return value here (for example if this was encrypted with a different key
        final String userPCBlowfishBase64 = "DlJgEjFZVuRRN5lCpInkOsawSaKK4hLwegZK/QgR1Thk380v5wL9pA1NZo7QHr7erlnry1vt2AqIyM8Fj2HBCsl1lierxE9EJ1typI2GpgMeG+HmceNdrlN6KGh4AmjLG3zCUPo8E+QzGVs/EO3PIAGyYYtuYbW++oJDr5xfY9DwK4Omq5GijZSSmdpOHiYelPMa1XLwT0D/kNCUm6EVfG6TKwxViNtGdyzknY7abNU7ucw2UWfjFe24hH0SL0hZMXjPQYtMnPl5J5qfjU4EXX1a/Ijn0IKUEk5BmY+ipc6irMI/Rrmumr46XAIU3uwWMxlbPxDtzyABsmGLbmG1vvqCQ6+cX2PQJ37oNcKqr4mV7ObN2EvWZ1uVbJlUdXeEQgghL3/ayatTs3hWwFGdNhgef8c8iX9wM5bEvxqqY9TMXEyLYLZeA8H6gNvJc6hRd0TQFkzUhjs=";
        Cookie[] cookies = new Cookie[]{
                new Cookie(WebRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCBlowfishBase64)
        };

        expect(mockRequest.getCookies()).andReturn(cookies).anyTimes();
        replay(mockRequest);

        WebRememberMeManager mgr = new WebRememberMeManager();
        PrincipalCollection collection = null;

        SerializationException se = null;
        try {
            collection = mgr.getRememberedPrincipals(context);
        } catch (SerializationException expected) {
            se = expected;
        }
        assertNotNull(se);

        verify(mockRequest);

        // Collection should be null since there was an error decrypting it
        assertTrue(collection == null);
    }

    @Test
    public void onLogout() {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebSubject mockSubject = createNiceMock(WebSubject.class);
        expect(mockSubject.getServletRequest()).andReturn(mockRequest).anyTimes();
        expect(mockSubject.getServletResponse()).andReturn(mockResponse).anyTimes();

        Cookie cookie = new Cookie(WebRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, "");
        cookie.setMaxAge(0);
        Cookie[] cookies = new Cookie[]{cookie};

        expect(mockRequest.getCookies()).andReturn(cookies);
        expect(mockRequest.getContextPath()).andReturn(null).anyTimes();
        mockResponse.addCookie(eq(cookie));

        replay(mockRequest);
        replay(mockResponse);
        replay(mockSubject);

        PrincipalCollection pc = new SimplePrincipalCollection("user", "test");
        WebRememberMeManager mgr = new WebRememberMeManager();
        mgr.onLogout(mockSubject);

        verify(mockSubject);
        verify(mockRequest);
        verify(mockResponse);
    }

}
