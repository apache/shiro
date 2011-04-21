package org.apache.shiro.web.servlet

import javax.servlet.FilterConfig
import javax.servlet.ServletContext
import static org.easymock.EasyMock.*

/**
 * Unit tests for the {@link IniShiroFilter} implementation.
 */
class IniShiroFilterTest extends GroovyTestCase {

    IniShiroFilter filter;
    FilterConfig mockFilterConfig;
    ServletContext mockServletContext;

    protected void setUp(String config) {
        mockFilterConfig = createMock(FilterConfig.class);
        mockServletContext = createMock(ServletContext.class);

        expect(mockFilterConfig.getServletContext()).andReturn(mockServletContext).anyTimes();
        expect(mockFilterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(mockFilterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_INIT_PARAM_NAME))).andReturn(config).once();
        expect(mockFilterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME))).andReturn(null).once();
    }

    protected void setUpWithPathConfig(String path) {
        mockFilterConfig = createMock(FilterConfig.class);
        mockServletContext = createMock(ServletContext.class);

        expect(mockFilterConfig.getServletContext()).andReturn(mockServletContext).anyTimes();
        expect(mockFilterConfig.getInitParameter(AbstractShiroFilter.STATIC_INIT_PARAM_NAME)).andReturn null
        expect(mockFilterConfig.getInitParameter(IniShiroFilter.CONFIG_INIT_PARAM_NAME)).andReturn(null).anyTimes();
        expect(mockFilterConfig.getInitParameter(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME)).andReturn(path).anyTimes();
    }

    public void tearDown() throws Exception {
        reset mockServletContext, mockFilterConfig
    }

    protected void replayAndVerify() throws Exception {
        replay mockServletContext, mockFilterConfig

        this.filter = new IniShiroFilter();
        this.filter.init(mockFilterConfig);

        verify mockFilterConfig, mockServletContext
    }


    void testDefaultConfig() {
        setUp(null);
        replayAndVerify();
    }

    void testSimpleConfig() {
        setUp("""
        [filters]
        authc.successUrl = /index.jsp
        """);
        replayAndVerify();
    }

    void testSimplePathConfig() {
        setUpWithPathConfig("classpath:IniShiroFilterTest.ini");
        replayAndVerify();
    }

}
