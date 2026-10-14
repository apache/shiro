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

import java.io.IOException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Replayed responses are captured and only applied to the browser on demand
 */
@ExtendWith(MockitoExtension.class)
class FormResubmitResponseTest {
    @Mock
    private HttpServletResponse browser;
    private FormResubmitResponse response;

    @BeforeEach
    void setUp() {
        response = new FormResubmitResponse(browser);
    }

    @Test
    void nothingReachesTheBrowserUntilApplied() throws IOException {
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
        response.setHeader("Cache-Control", "no-store");
        response.addHeader("Set-Cookie", "a=b");
        response.setIntHeader("X-Int", 1);
        response.addDateHeader("Expires", 0);
        response.addCookie(new Cookie("c", "d"));
        response.sendRedirect("/elsewhere");
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "boom");
        response.setContentLength(5);
        response.flushBuffer();
        response.resetBuffer();
        response.reset();
        // reading the buffer size is harmless
        verify(browser, atLeast(0)).getBufferSize();
        verifyNoMoreInteractions(browser);
    }

    @Test
    void appliesOperationsInOrder() {
        var cookie = new Cookie("c", "d");
        response.setHeader("X", "1");
        response.addHeader("X", "2");
        response.setIntHeader("N", 3);
        response.setDateHeader("D", 4L);
        response.addCookie(cookie);
        response.applyTo(browser);
        var order = inOrder(browser);
        order.verify(browser).setHeader("X", "1");
        order.verify(browser).addHeader("X", "2");
        order.verify(browser).setIntHeader("N", 3);
        order.verify(browser).setDateHeader("D", 4L);
        order.verify(browser).addCookie(cookie);
    }

    @Test
    void redirectOverloadsAreCaptured() throws IOException {
        response.sendRedirect("/a");
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND);
        response.sendRedirect("/b", HttpServletResponse.SC_SEE_OTHER);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_SEE_OTHER);
        response.sendRedirect("/c", false);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND);
        response.sendRedirect("/d", HttpServletResponse.SC_MOVED_PERMANENTLY, false);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_MOVED_PERMANENTLY);
        response.applyTo(browser);
        verify(browser).setHeader("Location", "/a");
        verify(browser).setHeader("Location", "/b");
        verify(browser).setHeader("Location", "/c");
        verify(browser).setHeader("Location", "/d");
        verify(browser, never()).sendRedirect(anyString());
        verify(browser, never()).sendRedirect(anyString(), anyInt(), any(Boolean.class));
    }

    @Test
    void errorsOnlyCaptureStatus() throws IOException {
        response.sendError(HttpServletResponse.SC_NOT_FOUND);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "nope");
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        verify(browser, never()).sendError(anyInt());
        verify(browser, never()).sendError(anyInt(), anyString());
    }

    @Test
    void flushAfterStreamClosedIsIgnored() throws IOException {
        when(browser.getCharacterEncoding()).thenReturn("UTF-8");
        when(browser.getBufferSize()).thenReturn((int) Short.MAX_VALUE);
        var stream = response.getOutputStream();
        assertThat(response.getOutputStream()).isSameAs(stream);
        stream.write("body".getBytes());
        // e.g. a download writer closes the stream, then PrimeFaces flushes the response
        stream.close();
        response.flushBuffer();
        assertThat(response.getBufferAsString()).isEqualTo("body");
        verify(browser, never()).flushBuffer();
    }

    @Test
    void resetDiscardsEverythingCaptured() throws IOException {
        when(browser.getCharacterEncoding()).thenReturn("UTF-8");
        when(browser.getBufferSize()).thenReturn((int) Short.MAX_VALUE);
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        response.setHeader("X", "1");
        response.addCookie(new Cookie("c", "d"));
        response.getWriter().print("body");
        response.reset();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getBufferAsString()).isEmpty();
        response.applyTo(browser);
        verify(browser, never()).setHeader(anyString(), anyString());
        verify(browser, never()).addCookie(any());
        verify(browser, never()).reset();
    }
}
