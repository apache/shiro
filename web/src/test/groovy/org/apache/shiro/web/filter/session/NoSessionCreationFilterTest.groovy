package org.apache.shiro.web.filter.session

import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import org.apache.shiro.subject.support.DefaultSubjectContext
import static org.easymock.EasyMock.*

/**
 * Unit tests for the {@link NoSessionCreationFilter} implementation.
 *
 * @since 1.2
 */
class NoSessionCreationFilterTest extends GroovyTestCase {

    void testDefault() {
        NoSessionCreationFilter filter = new NoSessionCreationFilter();

        def request = createStrictMock(ServletRequest)
        def response = createStrictMock(ServletResponse)

        request.setAttribute(eq(DefaultSubjectContext.SESSION_CREATION_ENABLED), eq(Boolean.FALSE))

        replay request, response

        assertTrue filter.onPreHandle(request, response, null)

        verify request, response
    }
}
