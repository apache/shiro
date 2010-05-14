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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.WebSubjectContext;
import org.apache.shiro.web.subject.support.DefaultWebSubjectContext;
import org.junit.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * TODO - Class JavaDoc
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class CookieRememberMeManagerTest {

    @Test
    public void onSuccessfulLogin() {

        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);
        WebSubject mockSubject = createNiceMock(WebSubject.class);
        expect(mockSubject.getServletRequest()).andReturn(mockRequest).anyTimes();
        expect(mockSubject.getServletResponse()).andReturn(mockResponse).anyTimes();

        CookieRememberMeManager mgr = new CookieRememberMeManager();
        org.apache.shiro.web.servlet.Cookie cookie = createMock(org.apache.shiro.web.servlet.Cookie.class);
        mgr.setCookie(cookie);

        //first remove any previous cookie
        cookie.removeFrom(isA(HttpServletRequest.class), isA(HttpServletResponse.class));

        //then ensure a new cookie is created by reading the template's attributes:
        expect(cookie.getName()).andReturn("rememberMe");
        expect(cookie.getValue()).andReturn(null);
        expect(cookie.getComment()).andReturn(null);
        expect(cookie.getDomain()).andReturn(null);
        expect(cookie.getPath()).andReturn(null);
        expect(cookie.getMaxAge()).andReturn(SimpleCookie.DEFAULT_MAX_AGE);
        expect(cookie.getVersion()).andReturn(SimpleCookie.DEFAULT_VERSION);
        expect(cookie.isSecure()).andReturn(false);
        expect(cookie.isHttpOnly()).andReturn(true);

        UsernamePasswordToken token = new UsernamePasswordToken("user", "secret");
        token.setRememberMe(true);
        AuthenticationInfo account = new SimpleAuthenticationInfo("user", "secret", "test");

        replay(mockSubject);
        replay(mockRequest);
        replay(cookie);

        mgr.onSuccessfulLogin(mockSubject, token, account);

        verify(mockRequest);
        verify(mockSubject);
        verify(cookie);
    }

    // SHIRO-69

    @Test
    public void getRememberedPrincipals() {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebSubjectContext context = new DefaultWebSubjectContext();
        context.setServletRequest(mockRequest);
        context.setServletResponse(mockResponse);

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);

        //The following base64 string was determined from the log output of the above 'onSuccessfulLogin' test.
        //This will have to change any time the PrincipalCollection implementation changes:
        final String userPCAesBase64 = "qk7spFqO1zoNLgq3qArE7bc8+J+Zvm1jz8lDSUmRiRlDQQx7jxG4+" +
                "QImiRpR7zO0d9oHH+7C3VeN9OvGMdjxtpbInMsLcGz4Q0u3M1fmyErn5Mr61chmNzQ8cLegpIKE3M+xMY" +
                "5JB1PRw7aEJdRxtHh80kiXZ5jeALvDP3hmFM7OF2CDKLIIa83XuBQvyrKGI9GhsxGTLkmNFknbfRsmN7v" +
                "NIDorceeaMkAetYf6GxDOw1ZK7yEbsydIHnqVWNHLen6DHC8pLkqMNOoGwXLeBroD6mRpoFf76J0VKBcd" +
                "C54Mg73S2R7wx9ZzSNJJrCi1KAilmThzm3Rm97EidUnYlWI0TM+zvMzNsLynIK4PoIG6HYQQfEI35qVRI" +
                "bCdbTlTnjfM/fPf7RWO8s4Z7KzszSQMJE9LgBudcyzrld5ZrWb11cianskNZMI8kzOITezjjqvWn5U4jg" +
                "Mb9a6qcpaNJcgaxV6NZRmof8cnet54wwE=";

        Cookie[] cookies = new Cookie[]{
                new Cookie(CookieRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCAesBase64)
        };

        expect(mockRequest.getCookies()).andReturn(cookies);
        replay(mockRequest);

        CookieRememberMeManager mgr = new CookieRememberMeManager();
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

        WebSubjectContext context = new DefaultWebSubjectContext();
        context.setServletRequest(mockRequest);
        context.setServletResponse(mockResponse);

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);

        // Simulate a bad return value here (for example if this was encrypted with a different key
        final String userPCAesBase64 = "garbage";
        Cookie[] cookies = new Cookie[]{
                new Cookie(CookieRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCAesBase64)
        };

        expect(mockRequest.getCookies()).andReturn(cookies).anyTimes();
        replay(mockRequest);

        CookieRememberMeManager mgr = new CookieRememberMeManager();
        PrincipalCollection collection = null;

        CryptoException ce = null;
        try {
            collection = mgr.getRememberedPrincipals(context);
        } catch (CryptoException expected) {
            ce = expected;
        }
        assertNotNull(ce);

        verify(mockRequest);

        // Collection should be null since there was an error decrypting it
        assertTrue(collection == null);
    }

    @Test
    public void onLogout() {
        CookieRememberMeManager mgr = new CookieRememberMeManager();
        org.apache.shiro.web.servlet.Cookie cookie = createMock(org.apache.shiro.web.servlet.Cookie.class);
        mgr.setCookie(cookie);

        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebSubject mockSubject = createNiceMock(WebSubject.class);
        expect(mockSubject.getServletRequest()).andReturn(mockRequest).anyTimes();
        expect(mockSubject.getServletResponse()).andReturn(mockResponse).anyTimes();
        expect(mockRequest.getContextPath()).andReturn(null).anyTimes();

        cookie.removeFrom(isA(HttpServletRequest.class), isA(HttpServletResponse.class));

        replay(mockRequest);
        replay(mockResponse);
        replay(mockSubject);
        replay(cookie);

        mgr.onLogout(mockSubject);

        verify(mockSubject);
        verify(mockRequest);
        verify(mockResponse);
        verify(cookie);
    }
}
