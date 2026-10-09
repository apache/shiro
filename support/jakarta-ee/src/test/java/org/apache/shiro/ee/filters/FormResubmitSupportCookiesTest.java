/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.ee.filters;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import static org.apache.shiro.ee.filters.FormResubmitSupport.SHIRO_FORM_DATA_KEY;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.addCookie;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.cookieName;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.deleteCookie;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Secure saved-form cookies can't be planted by another host, since they are host-prefixed
 */
@ExtendWith(MockitoExtension.class)
class FormResubmitSupportCookiesTest {
    private static final String SECURE_COOKIES = "org.apache.shiro.form-resubmit.secure-cookies";
    @Mock
    private ServletContext servletContext;
    @Mock
    private HttpServletResponse response;

    private Cookie added(boolean secure, String contextPath, int maxAge) {
        when(servletContext.getAttribute(SECURE_COOKIES)).thenReturn(secure);
        when(servletContext.getContextPath()).thenReturn(contextPath);
        if (maxAge == 0) {
            deleteCookie(response, servletContext, SHIRO_FORM_DATA_KEY);
        } else {
            addCookie(response, servletContext, SHIRO_FORM_DATA_KEY, "value", maxAge, true);
        }
        var cookie = ArgumentCaptor.forClass(Cookie.class);
        verify(response).addCookie(cookie.capture());
        return cookie.getValue();
    }

    @Test
    void secureCookieIsHostPrefixedAndRootScopedWithContextInName() {
        var cookie = added(true, "/my-app", 1);
        assertThat(cookie.getName()).isEqualTo("__Host-" + SHIRO_FORM_DATA_KEY + "%2Fmy-app");
        assertThat(cookie.getPath()).isEqualTo("/");
        assertThat(cookie.getSecure()).isTrue();
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.getDomain()).isNull();
        assertThat(cookie.getMaxAge()).isEqualTo(1);
    }

    @Test
    void secureRootContextNeedsNoSuffix() {
        assertThat(added(true, "", 1).getName()).isEqualTo("__Host-" + SHIRO_FORM_DATA_KEY);
    }

    @Test
    void insecureCookieKeepsLegacyNameAndContextPath() {
        var cookie = added(false, "/my-app", 1);
        assertThat(cookie.getName()).isEqualTo(SHIRO_FORM_DATA_KEY);
        assertThat(cookie.getPath()).isEqualTo("/my-app");
        assertThat(cookie.getSecure()).isFalse();
        assertThat(cookie.isHttpOnly()).isTrue();
    }

    @Test
    void deletionMatchesTheCookieItDeletes() {
        var cookie = added(true, "/my-app", 0);
        assertThat(cookie.getName()).isEqualTo(cookieName(servletContext, SHIRO_FORM_DATA_KEY));
        assertThat(cookie.getPath()).isEqualTo("/");
        assertThat(cookie.getSecure()).isTrue();
        assertThat(cookie.getMaxAge()).isZero();
    }

    @Test
    void distinctContextPathsNeverCollide() {
        when(servletContext.getAttribute(anyString())).thenReturn(true);
        when(servletContext.getContextPath()).thenReturn("/a/b", "/a.b", "/a_b", "/a%2Fb");
        assertThat(cookieName(servletContext, "k")).isEqualTo("__Host-k%2Fa%2Fb");
        assertThat(cookieName(servletContext, "k")).isEqualTo("__Host-k%2Fa.b");
        assertThat(cookieName(servletContext, "k")).isEqualTo("__Host-k%2Fa_b");
        assertThat(cookieName(servletContext, "k")).isEqualTo("__Host-k%2Fa%252Fb");
    }
}
