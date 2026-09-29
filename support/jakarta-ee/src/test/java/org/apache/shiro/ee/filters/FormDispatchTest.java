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

import jakarta.faces.context.FacesContext;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.support.WebDelegatingSubject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.apache.shiro.ee.filters.FormResubmitSupport.FORM_IS_RESUBMITTED;
import static org.apache.shiro.ee.filters.FormResubmitSupport.resubmitSavedForm;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings({"checkstyle:MethodCount", "checkstyle:MagicNumber"})
class FormDispatchTest {
    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse browserResponse = mock(HttpServletResponse.class);
    private final ServletContext context = mock(ServletContext.class);
    private final RequestDispatcher dispatcher = mock(RequestDispatcher.class);
    private final FormResubmitResponse response = new FormResubmitResponse(browserResponse);

    @BeforeEach
    void setup() {
        when(request.getContextPath()).thenReturn("/app");
        when(request.getServletContext()).thenReturn(context);
        when(request.getRequestURI()).thenReturn("/app/login");
        when(request.getRequestURL()).thenReturn(new StringBuffer("https://virtual.example/app/login"));
        when(request.getAttributeNames()).thenReturn(Collections.emptyEnumeration());
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(List.of("Content-Type", "Faces-Request")));
        when(context.getContextPath()).thenReturn("/app");
        when(context.getRequestDispatcher(anyString())).thenReturn(dispatcher);
    }

    @Test
    void replayReplacesBodyHeadersAndParametersButKeepsSession() throws Exception {
        var session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        String body = "name=J%C3%B6rg+%26+Co%2B&name=two&empty=&bare&equals=a=b%3Dc";
        var replay = new FormResubmitRequest(request, "/form?q=one", "POST", body);
        assertThat(replay.getParameterValues("name")).containsExactly("Jörg & Co+", "two");
        assertThat(replay.getParameter("empty")).isEmpty();
        assertThat(replay.getParameter("bare")).isEmpty();
        assertThat(replay.getParameter("equals")).isEqualTo("a=b=c");
        assertThat(replay.getParameter("username")).isNull();
        // Merged by the dispatcher, not twice by the wrapper.
        assertThat(replay.getParameterMap()).doesNotContainKey("q");
        assertThat(Collections.list(replay.getParameterNames())).containsExactly("name", "empty", "bare", "equals");
        assertThat(replay.getSession()).isSameAs(session);
        assertThat(replay.getRequestURI()).isEqualTo("/app/form");
        assertThat(replay.getRequestURL().toString()).isEqualTo("https://virtual.example/app/form");
        assertThat(replay.getQueryString()).isEqualTo("q=one");
        assertThat(replay.getContentLengthLong()).isEqualTo(body.getBytes(StandardCharsets.UTF_8).length);
        assertThat(replay.getIntHeader("content-length")).isEqualTo(replay.getContentLength());
        assertThat(replay.getHeader("faces-request")).isNull();
        assertThat(Collections.list(replay.getHeaderNames())).doesNotContain("Faces-Request");
        assertThat(Collections.list(replay.getHeaders(FORM_IS_RESUBMITTED.toUpperCase())))
                .containsExactly("true");
        assertThat(replay.getInputStream().isReady()).isTrue();
        assertThat(new String(replay.getInputStream().readAllBytes(), StandardCharsets.UTF_8)).isEqualTo(body);
        assertThat(replay.getInputStream().isFinished()).isTrue();
        assertThatThrownBy(replay::getReader).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void freshFacesCachesDoNotLeakAcrossDispatches() {
        when(request.getAttributeNames()).thenReturn(Collections.enumeration(List.of(
                "com.sun.faces.context", "org.omnifaces.facesviews.original_servlet_path", "applicationAttribute")));
        when(request.getAttribute("applicationAttribute")).thenReturn("keep");
        var replay = new FormResubmitRequest(request, "/form", "GET", "");
        assertThat(replay.getAttribute("com.sun.faces.context")).isNull();
        assertThat(replay.getAttribute("org.omnifaces.facesviews.original_servlet_path")).isNull();
        assertThat(replay.getAttribute("applicationAttribute")).isEqualTo("keep");
        replay.setAttribute("com.sun.faces.context", "new");
        verify(request, never()).setAttribute(anyString(), any());
    }

    @Test
    void forwardsWithinContextAndPreservesQuery() throws Exception {
        doAnswer(call -> {
            HttpServletRequest replay = call.getArgument(0);
            assertThat(replay.getMethod()).isEqualTo("POST");
            assertThat(replay.getReader().readLine()).isEqualTo("hello=world");
            assertThat(call.<HttpServletResponse>getArgument(1)).isSameAs(response);
            response.setHeader("Content-Security-Policy", "default-src 'self'");
            response.getWriter().write("done");
            return null;
        }).when(dispatcher).forward(any(), any());
        assertThat(resubmitSavedForm("hello=world", "https://ignored.invalid/app/form?q=a%26b",
                request, response, context, false, false)).isNull();
        verify(context).getRequestDispatcher("/form?q=a%26b");
        assertThat(response.getBodyAsString()).isEqualTo("done");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeader("Content-Security-Policy")).isEqualTo("default-src 'self'");
    }

    @Test
    void supportsContextRootAndRejectsOtherContexts() throws Exception {
        resubmitSavedForm("a=b", "/app?query=1", request, response, context, false, false);
        verify(context).getRequestDispatcher("/?query=1");
        assertThat(resubmitSavedForm("a=b", "/other/form", request, response, context, false, false)).isEqualTo("/app");
        verify(context, never()).getRequestDispatcher("/other/form");
    }

    @Test
    void supportsRootDeployment() throws Exception {
        when(request.getContextPath()).thenReturn("");
        resubmitSavedForm("a=b", "/form?query=1", request, response, context, false, false);
        verify(context).getRequestDispatcher("/form?query=1");
    }

    @Test
    void doesNotForwardToServletPrivateResources() throws Exception {
        for (String path : List.of("/app/WEB-INF/shiro.ini", "/app/META-INF/MANIFEST.MF", "/app/%57EB-INF/web.xml")) {
            assertThat(resubmitSavedForm("a=b", path, request, response, context, false, false)).isEqualTo("/app");
        }
        verify(context, never()).getRequestDispatcher(anyString());
    }

    @Test
    void forwardedTargetStillRunsItsAuthorizationChain() throws Exception {
        var filter = new ShiroFilter();
        filter.setServletContext(context);
        var resolver = new PathMatchingFilterChainResolver();
        resolver.getFilterChainManager().addFilter("reject", (req, resp, chain) ->
                ((HttpServletResponse) resp).sendError(HttpServletResponse.SC_FORBIDDEN));
        resolver.getFilterChainManager().createChain("/form", "reject");
        filter.setFilterChainResolver(resolver);
        var target = mock(FilterChain.class);
        var replay = new FormResubmitRequest(request, "/form", "POST", "a=b");
        filter.executeChain(replay, response, target);
        verify(target, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void statefulFacesGetsNewViewStateWithoutDecodingUserInput() throws Exception {
        List<String> methods = new ArrayList<>();
        doAnswer(call -> {
            HttpServletRequest replay = call.getArgument(0);
            HttpServletResponse result = call.getArgument(1);
            methods.add(replay.getMethod());
            if ("GET".equals(replay.getMethod())) {
                assertThat(replay.getParameterMap()).isEmpty();
                assertThat(replay.getContentType()).isNull();
                result.getWriter().write("<input name='jakarta.faces.ViewState' value='123:456'>");
                result.flushBuffer();
                assertThat(response.isCommitted()).isFalse();
            } else {
                assertThat(replay.getParameter("jakarta.faces.ViewState")).isEqualTo("123:456");
                assertThat(replay.getParameter("text")).isEqualTo("a&b+c=é");
                result.getWriter().write("submitted");
            }
            return null;
        }).when(dispatcher).forward(any(), any());
        resubmitSavedForm("text=a%26b%2Bc%3D%C3%A9&jakarta.faces.ViewState=1%3A2",
                "/app/form", request, response, context, false, false);
        assertThat(methods).containsExactly("GET", "POST");
        assertThat(response.getBodyAsString()).isEqualTo("submitted");
    }

    @Test
    void rememberedAjaxUsesTwoPostsAndConvertsRedirect() throws Exception {
        AtomicInteger posts = new AtomicInteger();
        var submittedFlash = new Cookie("flash", "submitted-message");
        var expiredFlash = new Cookie("flash", "expired-view");
        doAnswer(call -> {
            HttpServletRequest replay = call.getArgument(0);
            HttpServletResponse result = call.getArgument(1);
            if ("GET".equals(replay.getMethod())) {
                result.getWriter().write("<input name='jakarta.faces.ViewState' value='123:456'>");
            } else if (posts.incrementAndGet() == 1) {
                assertThat(replay.getParameter("jakarta.faces.partial.ajax")).isNull();
                assertThat(replay.getHeader("Faces-Request")).isNull();
                result.addCookie(submittedFlash);
                result.getWriter().write("discard this first response");
                result.flushBuffer();
            } else {
                assertThat(replay.getParameter("jakarta.faces.ViewState")).isEqualTo("1:2");
                assertThat(replay.getHeader("Faces-Request")).isNull();
                result.setHeader("Content-Security-Policy", "default-src 'none'");
                result.setContentLength(999);
                result.addCookie(expiredFlash);
                result.sendRedirect("/app/form?a=1&b=2");
            }
            return null;
        }).when(dispatcher).forward(any(), any());
        resubmitSavedForm("jakarta.faces.ViewState=1%3A2&jakarta.faces.partial.ajax=true",
                "/app/form?a=1&b=2", request, response, context, true, false);
        assertThat(posts.get()).isEqualTo(2);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getHeader("Location")).isNull();
        assertThat(response.getHeader("Content-Length")).isNull();
        assertThat(response.getHeader("Content-Security-Policy")).isEqualTo("default-src 'none'");
        assertThat(response.getBodyAsString()).isEqualTo(
                "<partial-response><redirect url=\"/app/form?a=1&amp;b=2\"></redirect></partial-response>");
        response.copyCookiesTo(browserResponse);
        verify(browserResponse).addCookie(submittedFlash);
        verify(browserResponse, never()).addCookie(expiredFlash);
    }

    @Test
    void clientStateSavingSkipsGetAndDoublePost() throws Exception {
        when(context.getInitParameter("jakarta.faces.STATE_SAVING_METHOD")).thenReturn("client");
        doAnswer(call -> {
            HttpServletRequest replay = call.getArgument(0);
            assertThat(replay.getMethod()).isEqualTo("POST");
            assertThat(replay.getParameter("jakarta.faces.ViewState")).isEqualTo("opaque+state");
            call.<HttpServletResponse>getArgument(1).getWriter().write("<partial-response/>");
            return null;
        }).when(dispatcher).forward(any(), any());
        resubmitSavedForm("jakarta.faces.ViewState=opaque%2Bstate&jakarta.faces.partial.ajax=true",
                "/app/form", request, response, context, true, false);
        verify(dispatcher).forward(any(), any());
        assertThat(response.getBodyAsString()).isEqualTo("<partial-response/>");
    }

    @Test
    void buffersDoNotCommitOrResetTheBrowserAndCookiesAreNotRewritten() throws Exception {
        var buffered = new FormResubmitResponse(browserResponse);
        buffered.setContentType("text/html; charset=ISO-8859-1");
        buffered.getWriter().write("discard");
        buffered.resetBuffer();
        buffered.getWriter().write("é");
        var cookie = new Cookie("flash", "value");
        cookie.setAttribute("SameSite", "Strict");
        buffered.addCookie(cookie);
        buffered.addHeader("Set-Cookie", "custom=value; SameSite=None; Secure");
        buffered.flushBuffer();
        assertThat(buffered.getBody()).containsExactly((byte) 0xe9);
        verify(browserResponse, never()).addCookie(any());
        buffered.copyCookiesTo(browserResponse);
        verify(browserResponse).addCookie(cookie);
        verify(browserResponse).addHeader("Set-Cookie", "custom=value; SameSite=None; Secure");
        verify(browserResponse, never()).flushBuffer();
        verify(browserResponse, never()).resetBuffer();
        verify(browserResponse, never()).getWriter();
    }

    @Test
    void failuresAreNotRetriedAndCallingFacesContextIsRestored() throws Exception {
        var outer = mock(FacesContext.class);
        FacesContextAccess.set(outer);
        try {
            doAnswer(call -> {
                assertThat(org.apache.shiro.ee.listeners.IniEnvironment.hasFacesContext()).isFalse();
                throw new ServletException("dispatch failed");
            }).when(dispatcher).forward(any(), any());
            assertThatThrownBy(() -> resubmitSavedForm("a=b", "/app/form", request, response, context, false, false))
                    .isInstanceOf(ServletException.class).hasMessage("dispatch failed");
            verify(dispatcher).forward(any(), any());
            assertThat(FacesContext.getCurrentInstance()).isSameAs(outer);
        } finally {
            FacesContextAccess.set(null);
        }
    }

    @Test
    void replayReusesBoundSubjectButAClientHeaderCannotSelectIt() {
        var subject = mock(WebSubject.class);
        var otherSubject = mock(WebSubject.class);
        var securityManager = mock(WebSecurityManager.class);
        when(securityManager.createSubject(any())).thenReturn(otherSubject);
        var filter = new ShiroFilter();
        filter.setSecurityManager(securityManager);
        ThreadContext.bind(subject);
        try {
            var replay = new FormResubmitRequest(request, "/form", "POST", "a=b");
            assertThat(filter.createSubject(new HttpServletRequestWrapper(replay), response)).isSameAs(subject);
            verify(securityManager, never()).createSubject(any());
            when(request.getHeader(FORM_IS_RESUBMITTED)).thenReturn("true");
            assertThat(filter.createSubject(request, response)).isSameAs(otherSubject);
        } finally {
            ThreadContext.remove();
        }
    }

    @Test
    void replayReusesExecutingSubjectOnScopedValueRuntimes() {
        var securityManager = mock(WebSecurityManager.class);
        var subject = new WebDelegatingSubject(null, false, "localhost", null, request, response, securityManager);
        var filter = new ShiroFilter();
        filter.setSecurityManager(securityManager);
        var replay = new FormResubmitRequest(request, "/form", "POST", "a=b");
        subject.execute((Runnable) () -> assertThat(filter.createSubject(replay, response)).isSameAs(subject));
        verify(securityManager, never()).createSubject(any());
    }

    private abstract static class FacesContextAccess extends FacesContext {
        static void set(FacesContext context) {
            setCurrentInstance(context);
        }
    }
}
