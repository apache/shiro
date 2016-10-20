package org.apache.shiro.web.filter.authc

import org.apache.shiro.subject.Subject
import org.junit.Test

import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Tests for {@link LogoutFilterTest}.
 */
class LogoutFilterTest {

    @Test
    void testLogoutViaGetMethod() {

        def request = mock(HttpServletRequest)
        def response = mock(HttpServletResponse)
        def subject = mock(Subject)

        // expect
        subject.logout()
        expect(request.getContextPath()).andReturn("")
        expect(response.encodeRedirectURL("/")).andReturn("/").anyTimes()
        response.sendRedirect("/")

        replay request, response, subject

        def filter = new LogoutFilter() {
            @Override
            protected Subject getSubject(ServletRequest servletRequest, ServletResponse servletResponse) {
                return subject
            }
        };

        filter.preHandle(request, response)

        verify request, response, subject
    }

    @Test
    void testLogoutViaGetMethodWhenPostOnlyEnabled() {

        def request = mock(HttpServletRequest)
        def response = mock(HttpServletResponse)
        def subject = mock(Subject)

        // expect
        expect(request.getMethod()).andReturn("GET")
        expect(response.setStatus(405))
        expect(response.setHeader("Allow", "POST"))

        replay request, response, subject

        def filter = new LogoutFilter() {
            @Override
            protected Subject getSubject(ServletRequest servletRequest, ServletResponse servletResponse) {
                return subject
            }
        };
        filter.setPostOnlyLogout(true)
        filter.preHandle(request, response)

        verify request, response, subject
    }

    @Test
    void testLogoutViaPostMethodWhenPostOnlyEnabled() {

        def request = mock(HttpServletRequest)
        def response = mock(HttpServletResponse)
        def subject = mock(Subject)

        // expect
        expect(request.getMethod()).andReturn("Post")
        subject.logout()
        expect(request.getContextPath()).andReturn("")
        expect(response.encodeRedirectURL("/")).andReturn("/").anyTimes()
        response.sendRedirect("/")

        replay request, response, subject

        def filter = new LogoutFilter() {
            @Override
            protected Subject getSubject(ServletRequest servletRequest, ServletResponse servletResponse) {
                return subject
            }
        };
        filter.setPostOnlyLogout(true)
        filter.preHandle(request, response)

        verify request, response, subject
    }
}
