/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web.servlet;

import static org.easymock.EasyMock.*;
import org.jsecurity.mgt.SecurityManager;
import org.junit.Test;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class JSecurityFilterTest {

    private JSecurityFilter filter;
    private FilterConfig mockFilterConfig;
    private ServletContext mockServletContext;

    protected void setUp(String config) {
        mockFilterConfig = createMock(FilterConfig.class);
        mockServletContext = createMock(ServletContext.class);

        expect(mockFilterConfig.getServletContext()).andReturn(mockServletContext);
        expect(mockFilterConfig.getInitParameter(JSecurityFilter.CONFIG_CLASS_NAME_INIT_PARAM_NAME)).andReturn(null).once();
        expect(mockFilterConfig.getInitParameter(JSecurityFilter.CONFIG_INIT_PARAM_NAME)).andReturn(config).once();

        mockServletContext.setAttribute(eq(JSecurityFilter.SECURITY_MANAGER_CONTEXT_KEY), isA(SecurityManager.class));
    }

    public void tearDown() throws Exception {
        reset(mockServletContext);
        reset(mockFilterConfig);

        replay(mockServletContext);

        //this.filter.destroy();

        verify(mockServletContext);
        verify(mockFilterConfig);
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
        setUp(null);
        replayAndVerify();
    }

    @Test
    public void testSimpleConfig() throws Exception {
        setUp("[interceptors]\n" +
                "authc.successUrl = /index.jsp");
        replayAndVerify();
    }
}
