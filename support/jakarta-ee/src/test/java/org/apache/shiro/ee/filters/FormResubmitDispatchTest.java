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

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FormResubmitDispatchTest {
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private ServletContext servletContext;
    @Mock
    private RequestDispatcher dispatcher;
    @Mock
    private ServletOutputStream output;

    @Test
    void afterLoginReplayUsesOnePostAndNoGet() throws Exception {
        replayAfterLogin(false);
    }

    @Test
    void afterLoginAjaxReplayProcessesCommandThenRedirects() throws Exception {
        replayAfterLogin(true);
    }

    private void replayAfterLogin(boolean ajaxForm) throws Exception {
        when(request.getContextPath()).thenReturn("/app");
        when(request.getRequestURL()).thenReturn(new StringBuffer("https://localhost/app/form.xhtml"));
        when(request.getServletContext()).thenReturn(servletContext);
        when(request.getAttributeNames()).thenReturn(Collections.emptyEnumeration());
        when(servletContext.getContextPath()).thenReturn("/app");
        when(servletContext.getRequestDispatcher("/form.xhtml")).thenReturn(dispatcher);
        if (!ajaxForm) {
            when(response.getOutputStream()).thenReturn(output);
        }
        byte[] result = "replayed".getBytes(StandardCharsets.UTF_8);
        doAnswer(invocation -> {
            HttpServletRequest replay = invocation.getArgument(0);
            HttpServletResponse captured = invocation.getArgument(1);
            assertThat(replay.getMethod()).isEqualTo("POST");
            assertThat(replay.getParameter("jakarta.faces.ViewState")).isEqualTo("123:456");
            assertThat(replay.getParameter("name")).isEqualTo("Jack & Jill");
            assertThat(FormResubmitRequest.isResubmit(replay)).isTrue();
            if (ajaxForm) {
                assertThat(replay.getParameter("jakarta.faces.partial.ajax")).isNull();
                assertThat(replay.getParameter("jakarta.faces.source")).isNull();
                assertThat(replay.getParameter("form:submit")).isEmpty();
                assertThat(replay.getHeader("Faces-Request")).isNull();
            }
            captured.getOutputStream().write(result);
            return null;
        }).when(dispatcher).forward(any(), any());

        String formData = "name=Jack+%26+Jill&jakarta.faces.ViewState=123%3A456"
                + (ajaxForm ? "&jakarta.faces.partial.ajax=true&jakarta.faces.source=form%3Asubmit" : "");
        FormResubmitSupport.resubmitSavedForm(formData,
                "/app/form.xhtml", request, response);

        verify(dispatcher).forward(any(), any());
        if (ajaxForm) {
            verify(response).sendRedirect("/app/form.xhtml");
            verify(response, never()).getOutputStream();
        } else {
            verify(output).write(result);
            verify(response, never()).sendRedirect(any());
        }
    }
}
