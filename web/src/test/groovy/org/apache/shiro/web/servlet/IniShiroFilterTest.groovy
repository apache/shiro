package org.apache.shiro.web.servlet

import javax.servlet.FilterConfig
import javax.servlet.ServletContext
import org.apache.shiro.io.ResourceUtils
import static org.easymock.EasyMock.*

/**
 * Unit tests for the {@link IniShiroFilter} implementation.
 */
class IniShiroFilterTest extends GroovyTestCase {

    void testDefaultWebInfConfig() {
        def filterConfig = createStrictMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)
        def inputStream = ResourceUtils.getResourceAsStream("classpath:IniShiroFilterTest.ini")

        expect(filterConfig.getServletContext()).andReturn servletContext
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(IniShiroFilter.CONFIG_INIT_PARAM_NAME)).andReturn null
        expect(filterConfig.getInitParameter(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME)).andReturn null
        expect(servletContext.getResourceAsStream(IniShiroFilter.DEFAULT_WEB_INI_RESOURCE_PATH)).andReturn inputStream

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        filter.init(filterConfig)

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
