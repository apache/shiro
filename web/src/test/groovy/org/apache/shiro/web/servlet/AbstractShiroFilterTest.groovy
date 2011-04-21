package org.apache.shiro.web.servlet

import javax.servlet.FilterConfig
import javax.servlet.ServletContext
import org.apache.shiro.SecurityUtils
import org.apache.shiro.UnavailableSecurityManagerException
import org.apache.shiro.web.mgt.WebSecurityManager
import static org.easymock.EasyMock.*

/**
 * Unit tests for the {@link AbstractShiroFilter} implementation.
 */
class AbstractShiroFilterTest extends GroovyTestCase {

    void testInit() {

        SecurityUtils.securityManager = null

        def securityManager = createStrictMock(WebSecurityManager)
        def filterConfig = createStrictMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)

        expect(filterConfig.servletContext).andReturn servletContext
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null

        replay securityManager, filterConfig, servletContext

        AbstractShiroFilter filter = new AbstractShiroFilter() {}
        filter.securityManager = securityManager

        filter.init(filterConfig)

        try {
            SecurityUtils.getSecurityManager()
            fail "AbstractShiroFilter initialization should not have resulted in a static SecurityManager reference."
        } catch (UnavailableSecurityManagerException expected) {
        }

        verify securityManager, filterConfig, servletContext
    }

    void testInitWithStaticReference() {

        SecurityUtils.securityManager = null

        def securityManager = createStrictMock(WebSecurityManager)
        def filterConfig = createStrictMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)

        expect(filterConfig.servletContext).andReturn servletContext
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn "true"

        replay securityManager, filterConfig, servletContext

        AbstractShiroFilter filter = new AbstractShiroFilter(){}
        filter.securityManager = securityManager

        try {
            filter.init(filterConfig)

            assertSame securityManager, SecurityUtils.securityManager

            verify securityManager, filterConfig, servletContext
        } finally {
            SecurityUtils.securityManager = null
        }
    }

}
