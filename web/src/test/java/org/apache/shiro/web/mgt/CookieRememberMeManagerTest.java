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
import org.apache.shiro.lang.codec.Base64;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.WebSubjectContext;
import org.apache.shiro.web.subject.support.DefaultWebSubjectContext;
import org.junit.jupiter.api.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.isA;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for the {@link CookieRememberMeManager} implementation.
 *
 * @since 1.0
 */
class CookieRememberMeManagerTest {

    @Test
    void onSuccessfulLogin() {

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
        expect(cookie.getSameSite()).andReturn(org.apache.shiro.web.servlet.Cookie.SameSiteOptions.LAX);

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

    // SHIRO-183
    @Test
    void getRememberedSerializedIdentityReturnsNullForDeletedCookie() {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebSubjectContext context = new DefaultWebSubjectContext();
        context.setServletRequest(mockRequest);
        context.setServletResponse(mockResponse);

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);

        Cookie[] cookies = new Cookie[] {
                new Cookie(CookieRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME,
                        org.apache.shiro.web.servlet.Cookie.DELETED_COOKIE_VALUE)
        };

        expect(mockRequest.getCookies()).andReturn(cookies);
        replay(mockRequest);

        CookieRememberMeManager mgr = new CookieRememberMeManager();
        assertThat(mgr.getRememberedSerializedIdentity(context)).isNull();
    }


    // SHIRO-69
    @Test
    void getRememberedPrincipals() {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebSubjectContext context = new DefaultWebSubjectContext();
        context.setServletRequest(mockRequest);
        context.setServletResponse(mockResponse);

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);

        //The following base64 string was determined from the log output of the above 'onSuccessfulLogin' test.
        //This will have to change any time the PrincipalCollection implementation changes:
        final String userPCAesBase64 = "0o6DCfePYTjK4q579qzUFEfkeGRvbBOdKHp2y8/nGAltt1Vz8uW0Z8igeO"
                 + "Tq/yBmcw25f3Q0ui/Leg3x0iQZWhw9Bbu0mFHmHsGxEd6mPwtUpSegIjyX5c/kZpqnb7QLdajPWiczX8P"
                 + "Oc2Eku5+8ye1u38Y8uKlklHxcYCPh0pRiDSBxfjPsLaDfOpGbmPjZd4SVg68i/++TvUjqBNJyb+pDix3f"
                 + "PeuPvReWGcE50iovezVZrEfDOAQ0cZYW35ShypMWOmE9yZnb+p8++StDyAUegryyuIa4pjuRzfMh9D+sN"
                 + "F9tm/EnDC1VCer2S/a0AGlWAQiM7jrWt1sNinZcKIrvShaWI21tONJt8WhozNS2H72lk4p92rfLNHeglT"
                 + "xObxIYxLfTI9KiToSe1nYmpQmbBO8x1wWDkWBG//EqRvhgbIfQVqJp12T0fJC1nFuZuVhw/ZanaAZGDk8"
                 + "7aLMiw3T6FBZtWaspgvfH+0TJrTD8Ra386ekNXNN8JW8=";

        Cookie[] cookies = new Cookie[] {
                new Cookie(CookieRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCAesBase64)
        };

        expect(mockRequest.getCookies()).andReturn(cookies);
        replay(mockRequest);

        CookieRememberMeManager mgr = new CookieRememberMeManager();
        mgr.setCipherKey(Base64.decode("kPH+bIxk5D2deZiIxcaaaA=="));
        PrincipalCollection collection = mgr.getRememberedPrincipals(context);

        verify(mockRequest);

        assertThat(collection).isNotNull();
        //noinspection ConstantConditions
        assertThat(collection.iterator().next()).isEqualTo("user");
    }

    @Test
    void getRememberedPrincipalsNoMoreDefaultCipher() {
        assertThatExceptionOfType(CryptoException.class).isThrownBy(() -> {
            HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
            HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
            WebSubjectContext context = new DefaultWebSubjectContext();
            context.setServletRequest(mockRequest);
            context.setServletResponse(mockResponse);

            expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);
            expect(mockRequest.getContextPath()).andReturn("/test");


            //The following base64 string was determined from the log output of the above 'onSuccessfulLogin' test.
            //This will have to change any time the PrincipalCollection implementation changes:
            final String userPCAesBase64 = "0o6DCfePYTjK4q579qzUFEfkeGRvbBOdKHp2y8/nGAltt1Vz8uW0Z8igeO"
                    + "Tq/yBmcw25f3Q0ui/Leg3x0iQZWhw9Bbu0mFHmHsGxEd6mPwtUpSegIjyX5c/kZpqnb7QLdajPWiczX8P"
                    + "Oc2Eku5+8ye1u38Y8uKlklHxcYCPh0pRiDSBxfjPsLaDfOpGbmPjZd4SVg68i/++TvUjqBNJyb+pDix3f"
                    + "PeuPvReWGcE50iovezVZrEfDOAQ0cZYW35ShypMWOmE9yZnb+p8++StDyAUegryyuIa4pjuRzfMh9D+sN"
                    + "F9tm/EnDC1VCer2S/a0AGlWAQiM7jrWt1sNinZcKIrvShaWI21tONJt8WhozNS2H72lk4p92rfLNHeglT"
                    + "xObxIYxLfTI9KiToSe1nYmpQmbBO8x1wWDkWBG//EqRvhgbIfQVqJp12T0fJC1nFuZuVhw/ZanaAZGDk8"
                    + "7aLMiw3T6FBZtWaspgvfH+0TJrTD8Ra386ekNXNN8JW8=";

            Cookie[] cookies = new Cookie[]{
                    new Cookie(CookieRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCAesBase64)
            };

            expect(mockRequest.getCookies()).andReturn(cookies);
            replay(mockRequest);

            CookieRememberMeManager mgr = new CookieRememberMeManager();
            // without the old default cipher set, this will fail (expected)
            // mgr.setCipherKey( Base64.decode("kPH+bIxk5D2deZiIxcaaaA=="));
            // this will throw a CryptoException
            mgr.getRememberedPrincipals(context);
        });
    }

    // SHIRO-69
    @SuppressWarnings("checkstyle:MethodName")
    @Test
    void getRememberedPrincipalsDecryptionError_whenWrongCookieValue() {
        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);

        WebSubjectContext context = new DefaultWebSubjectContext();
        context.setServletRequest(mockRequest);
        context.setServletResponse(mockResponse);

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);

        // Simulate a bad return value here (valid Base64 does not contain key)
        String userPCAesBase64 = "garbage";
        Cookie[] cookies = new Cookie[] {
                new Cookie(CookieRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCAesBase64)
        };

        expect(mockRequest.getCookies()).andReturn(cookies).anyTimes();
        replay(mockRequest);

        CookieRememberMeManager mgr = new CookieRememberMeManager();
        assertThrows(CryptoException.class,
                () -> mgr.getRememberedPrincipals(context),
                "CryptoException should be thrown on invalid cookies");
    }

    @SuppressWarnings("checkstyle:MethodName")
    @Test
    void getRememberedPrincipalsDecryptionError_whenInvalidBase64() {
        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);

        WebSubjectContext context = new DefaultWebSubjectContext();
        context.setServletRequest(mockRequest);
        context.setServletResponse(mockResponse);

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);

        // Simulate a bad return value here (not valid Base64)
        String userPCAesBase64 = "InvalidBase64";
        Cookie[] cookies = new Cookie[] {
                new Cookie(CookieRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, userPCAesBase64)
        };

        expect(mockRequest.getCookies()).andReturn(cookies).anyTimes();
        replay(mockRequest);

        CookieRememberMeManager mgr = new CookieRememberMeManager();
        PrincipalCollection rememberedPrincipals = mgr.getRememberedPrincipals(context);
        assertThat(rememberedPrincipals).as("rememberedPrincipals should be null on invalid cookies.").isNull();
    }

    @Test
    void onLogout() {
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

    @Test
    void shouldIgnoreInvalidCookieValues() {
        // given
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        WebSubjectContext context = new DefaultWebSubjectContext();
        context.setServletRequest(mockRequest);
        context.setServletResponse(mockResponse);

        CookieRememberMeManager mgr = new CookieRememberMeManager();
        Cookie[] cookies = new Cookie[] {
                new Cookie(CookieRememberMeManager.DEFAULT_REMEMBER_ME_COOKIE_NAME, UUID.randomUUID().toString() + "%%ldapRealm")
        };

        expect(mockRequest.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)).andReturn(null);
        expect(mockRequest.getContextPath()).andReturn(null);
        expect(mockRequest.getCookies()).andReturn(cookies);
        replay(mockRequest);

        // when
        final byte[] rememberedSerializedIdentity = mgr.getRememberedSerializedIdentity(context);

        // then
        assertThat(rememberedSerializedIdentity).as("should ignore invalid cookie values").isNull();
    }

    @SuppressWarnings("checkstyle:MagicNumber")
    @Test
    void ensurePaddingShouldAddEnoughEquals() {
        CookieRememberMeManager mgr = new CookieRememberMeManager();
        StringBuilder stringToTest = new StringBuilder("A string to test padding");
        for (int i = 0; i < 10; i++) {
            stringToTest.append("x");
            String encoded = Base64.encodeToString(stringToTest.toString().getBytes());
            while (encoded.endsWith("=")) {
                encoded = encoded.substring(0, encoded.length() - 1);
            }
            String base64 = mgr.ensurePadding(encoded);
            assertDoesNotThrow(() -> Base64.decode(base64), "Error decoding " + stringToTest);
        }
    }
}
