package org.jsecurity.web.servlet;

import static org.easymock.EasyMock.*;
import org.jsecurity.web.WebSecurityManager;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class JSecurityFilterTest {

    private JSecurityFilter filter;
    private FilterConfig mockFilterConfig;
    private ServletContext mockServletContext;

    @Before
    public void setUp() throws Exception {
        mockFilterConfig = createMock(FilterConfig.class);
        mockServletContext = createMock(ServletContext.class);

        expect(mockFilterConfig.getServletContext()).andReturn(mockServletContext);
        expect(mockServletContext.getInitParameter(ServletContextSupport.SESSION_MODE_CONTEXT_PARAM_NAME)).andReturn(null).atLeastOnce();
        expect(mockServletContext.getAttribute(SecurityManagerListener.SECURITY_MANAGER_CONTEXT_KEY)).andReturn(null).atLeastOnce();
        mockServletContext.setAttribute(eq(SecurityManagerListener.SECURITY_MANAGER_CONTEXT_KEY),isA(WebSecurityManager.class));
    }

    @After
    public void tearDown() throws Exception {
        reset(mockServletContext);
        reset(mockFilterConfig);

        mockServletContext.removeAttribute(SecurityManagerListener.SECURITY_MANAGER_CONTEXT_KEY);
        replay(mockServletContext);

        filter.destroy();

        verify(mockServletContext);
    }

    protected void replayAndVerify() throws Exception {
        replay(mockServletContext);
        replay(mockFilterConfig);

        this.filter = new JSecurityFilter();
        this.filter.init(mockFilterConfig);

        verify(mockFilterConfig);
        verify(mockServletContext);
    }


    @Test
    public void testDefaultConfig() throws Exception {
        expect(mockFilterConfig.getInitParameter("interceptors")).andReturn(null);
        expect(mockFilterConfig.getInitParameter("urls")).andReturn(null);
        expect(mockFilterConfig.getInitParameter("unauthorizedPage")).andReturn(null);
        replayAndVerify();
    }

    @Test
    public void testCustomInterceptorConfig() throws Exception {
        String interceptors = "authc = org.jsecurity.web.filter.authc.BasicHttpAuthenticationWebInterceptor\n" +
                "              authc.applicationName = JSecurity Quickstart";

        expect(mockFilterConfig.getInitParameter("interceptors")).andReturn(interceptors);
        expect(mockFilterConfig.getInitParameter("urls")).andReturn(null);
        expect(mockFilterConfig.getInitParameter("unauthorizedPage")).andReturn(null);
        replayAndVerify();
    }

    //TODO - make this exception a subclass of ServletException to indicate invalid configuration?
    @Test(expected = ServletException.class)
    public void testCustomInterceptorConfigInvalidKeyValuePair() throws Exception {
        String interceptors = "authc = org.jsecurity.web.filter.authc.BasicHttpAuthenticationWebInterceptor\n" +
                "              authc.applicationName JSecurity Quickstart";

        expect(mockFilterConfig.getInitParameter("interceptors")).andReturn(interceptors);
        expect(mockFilterConfig.getInitParameter("urls")).andReturn(null);
        expect(mockFilterConfig.getInitParameter("unauthorizedPage")).andReturn(null);
        replayAndVerify();
    }

}
