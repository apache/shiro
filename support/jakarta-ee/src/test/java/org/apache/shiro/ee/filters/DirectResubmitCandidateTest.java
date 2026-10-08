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

import static jakarta.faces.application.StateManager.STATE_SAVING_METHOD_CLIENT;
import static jakarta.faces.application.StateManager.STATE_SAVING_METHOD_PARAM_NAME;
import static org.apache.shiro.ee.filters.FormResubmitSupport.isDirectResubmitCandidate;
import static org.apache.shiro.ee.filters.FormResubmitSupport.isFormUrlEncoded;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Replaying a form in place, without a login flow, for remembered and anonymous subjects
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DirectResubmitCandidateTest {
    private static final String FORM_RESUBMIT_DISABLED_PARAM = "org.apache.shiro.form-resubmit.disabled";
    private static final String FORM_RESUBMIT_ANONYMOUS_DISABLED_PARAM = "org.apache.shiro.form-resubmit.anonymous.disabled";

    @Mock
    private HttpServletRequest request;
    @Mock
    private ServletContext servletContext;
    @Mock
    private Subject subject;

    @BeforeEach
    void anonymousSameOriginFormPostWithExpiredSession() {
        when(request.getServletContext()).thenReturn(servletContext);
        when(request.getMethod()).thenReturn("POST");
        when(request.getContentType()).thenReturn("application/x-www-form-urlencoded; charset=UTF-8");
        when(request.getHeader("Sec-Fetch-Site")).thenReturn("same-origin");
        when(request.getRequestedSessionId()).thenReturn("expired-session-id");
        when(subject.isAuthenticated()).thenReturn(false);
        when(subject.isRemembered()).thenReturn(false);
    }

    @Test
    void anonymousExpiredSessionIsReplayed() {
        assertThat(isDirectResubmitCandidate(subject, request)).isTrue();
    }

    @Test
    void anonymousWithoutPriorSessionIsNotReplayed() {
        when(request.getRequestedSessionId()).thenReturn(null);
        assertThat(isDirectResubmitCandidate(subject, request)).isFalse();
    }

    @Test
    void rememberedIsReplayedEvenWithoutPriorSession() {
        when(request.getRequestedSessionId()).thenReturn(null);
        when(subject.isRemembered()).thenReturn(true);
        assertThat(isDirectResubmitCandidate(subject, request)).isTrue();
    }

    @Test
    void anonymousReplayCanBeDisabled() {
        when(servletContext.getAttribute(FORM_RESUBMIT_ANONYMOUS_DISABLED_PARAM)).thenReturn(Boolean.TRUE);
        assertThat(isDirectResubmitCandidate(subject, request)).isFalse();
    }

    @Test
    void anonymousDisablingKeepsRememberedReplay() {
        when(servletContext.getAttribute(FORM_RESUBMIT_ANONYMOUS_DISABLED_PARAM)).thenReturn(Boolean.TRUE);
        when(subject.isRemembered()).thenReturn(true);
        assertThat(isDirectResubmitCandidate(subject, request)).isTrue();
    }

    @Test
    void globalDisablingStopsAllReplays() {
        when(servletContext.getAttribute(FORM_RESUBMIT_DISABLED_PARAM)).thenReturn(Boolean.TRUE);
        assertThat(isDirectResubmitCandidate(subject, request)).isFalse();
        when(subject.isRemembered()).thenReturn(true);
        assertThat(isDirectResubmitCandidate(subject, request)).isFalse();
    }

    @Test
    void clientStateSavingNeedsNoReplay() {
        when(servletContext.getInitParameter(STATE_SAVING_METHOD_PARAM_NAME)).thenReturn(STATE_SAVING_METHOD_CLIENT);
        assertThat(isDirectResubmitCandidate(subject, request)).isFalse();
    }

    @Test
    void getIsNotReplayed() {
        when(request.getMethod()).thenReturn("GET");
        assertThat(isDirectResubmitCandidate(subject, request)).isFalse();
    }

    @Test
    void crossSitePostIsNotReplayed() {
        when(request.getHeader("Sec-Fetch-Site")).thenReturn("cross-site");
        assertThat(isDirectResubmitCandidate(subject, request)).isFalse();
    }

    @Test
    void nonFormContentIsNotReplayed() {
        when(request.getContentType()).thenReturn("application/json");
        assertThat(isDirectResubmitCandidate(subject, request)).isFalse();
        when(request.getContentType()).thenReturn("multipart/form-data; boundary=xyz");
        assertThat(isDirectResubmitCandidate(subject, request)).isFalse();
    }

    @Test
    void formContentTypeDetection() {
        when(request.getContentType()).thenReturn(null);
        assertThat(isFormUrlEncoded(request)).isFalse();
        when(request.getContentType()).thenReturn("Application/X-WWW-Form-UrlEncoded");
        assertThat(isFormUrlEncoded(request)).isTrue();
        when(request.getContentType()).thenReturn(" application/x-www-form-urlencoded ;charset=ISO-8859-1");
        assertThat(isFormUrlEncoded(request)).isTrue();
    }
}
