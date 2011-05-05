package org.apache.shiro.web.servlet

import javax.servlet.FilterConfig
import javax.servlet.ServletContext
import javax.servlet.ServletException
import org.apache.shiro.io.ResourceUtils
import static org.easymock.EasyMock.*

/**
 * Unit tests for the {@link IniShiroFilter} implementation.
 */
class IniShiroFilterTest extends GroovyTestCase {

    void testDefaultWebInfConfig() {
        def filterConfig = createMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)
        InputStream inputStream = ResourceUtils.getInputStreamForPath("classpath:IniShiroFilterTest.ini")
        assertNotNull inputStream

        expect(filterConfig.getServletContext()).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME))).andReturn null
        //simulate the servlet context resource of /WEB-INF/shiro.ini to be our test file above:
        expect(servletContext.getResourceAsStream(eq(IniShiroFilter.DEFAULT_WEB_INI_RESOURCE_PATH))).andReturn(inputStream)

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        filter.init(filterConfig)

        verify filterConfig, servletContext
    }

    void testResourceConfig() {
        def filterConfig = createMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)

        expect(filterConfig.getServletContext()).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME))).andReturn "classpath:IniShiroFilterTest.ini"

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        filter.init(filterConfig)

        verify filterConfig, servletContext
    }

    void testResourceConfigWithoutResource() {
        def filterConfig = createMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)
        def nonExistentResource = "/WEB-INF/foo.ini"

        expect(filterConfig.getServletContext()).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME))).andReturn nonExistentResource
        expect(servletContext.getResourceAsStream(eq(nonExistentResource))).andReturn(null)

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        try {
            filter.init(filterConfig)
            fail "Filter init should have failed due to specified nonexisting resource path."
        } catch (ServletException expected) {
        }

        verify filterConfig, servletContext
    }

    void testDefaultClasspathConfig() {

        def filterConfig = createStrictMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)

        expect(filterConfig.getServletContext()).andReturn servletContext
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(IniShiroFilter.CONFIG_INIT_PARAM_NAME)).andReturn null
        expect(filterConfig.getInitParameter(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME)).andReturn null
        expect(servletContext.getResourceAsStream(IniShiroFilter.DEFAULT_WEB_INI_RESOURCE_PATH)).andReturn null

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        filter.init(filterConfig)

        verify filterConfig, servletContext
    }


    void testSimpleConfig() {
        def config = """
        [filters]
        authc.successUrl = /index.jsp
        """
        def filterConfig = createMock(FilterConfig)
        def servletContext = createMock(ServletContext)

        expect(filterConfig.getServletContext()).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_INIT_PARAM_NAME))).andReturn config
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME))).andReturn null

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        filter.init(filterConfig)

        verify filterConfig, servletContext
    }

}
