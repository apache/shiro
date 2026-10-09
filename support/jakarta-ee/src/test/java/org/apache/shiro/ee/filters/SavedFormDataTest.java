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

import static org.apache.shiro.ee.filters.FormResubmitSupport.FORM_DATA_CACHE;
import static org.apache.shiro.ee.filters.FormResubmitSupport.SHIRO_FORM_DATA_KEY;
import static org.apache.shiro.ee.filters.FormResubmitSupport.getSavedFormDataKey;
import static org.apache.shiro.ee.filters.FormResubmitSupport.hasSavedFormData;
import static org.apache.shiro.ee.filters.FormResubmitSupport.isFormDataDiscarded;
import static org.apache.shiro.ee.filters.Forms.DISCARD_FORM_DATA_PARAMETER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import java.util.UUID;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Login-page view of saved form data: whether any is waiting, and the user's choice to discard it
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SavedFormDataTest {
    @Mock
    private HttpServletRequest request;
    @Mock
    private ServletContext servletContext;
    private final DefaultSecurityManager securityManager = new DefaultSecurityManager();

    @BeforeEach
    void bindSecurityManager() {
        when(request.getServletContext()).thenReturn(servletContext);
        securityManager.setCacheManager(new MemoryConstrainedCacheManager());
        ThreadContext.bind(securityManager);
    }

    @AfterEach
    void unbindSecurityManager() {
        ThreadContext.unbindSecurityManager();
    }

    private void savedFormDataCookie(String value) {
        when(request.getCookies()).thenReturn(new Cookie[] {new Cookie(SHIRO_FORM_DATA_KEY, value)});
    }

    @Test
    void nothingSavedWithoutCookie() {
        assertThat(getSavedFormDataKey(request)).isNull();
        assertThat(hasSavedFormData(request)).isFalse();
    }

    @Test
    void malformedCookieIsIgnored() {
        savedFormDataCookie("not-a-uuid");
        assertThat(getSavedFormDataKey(request)).isNull();
        assertThat(hasSavedFormData(request)).isFalse();
    }

    @Test
    void savedOnlyWhileFormDataIsCached() {
        var key = UUID.randomUUID();
        savedFormDataCookie(key.toString());
        assertThat(getSavedFormDataKey(request)).isEqualTo(key);
        assertThat(hasSavedFormData(request)).as("stale cookie").isFalse();
        securityManager.getCacheManager().getCache(FORM_DATA_CACHE).put(key, "firstName=Jack");
        assertThat(hasSavedFormData(request)).isTrue();
    }

    @Test
    void discardOnlyWhenAsked() {
        assertThat(isFormDataDiscarded(request)).as("no checkbox").isFalse();
        when(request.getParameter(DISCARD_FORM_DATA_PARAMETER)).thenReturn("on");
        assertThat(isFormDataDiscarded(request)).as("checked checkbox").isTrue();
        when(request.getParameter(DISCARD_FORM_DATA_PARAMETER)).thenReturn("false");
        assertThat(isFormDataDiscarded(request)).isFalse();
    }
}
