/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.spring;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.servlet.ShiroFilter;
import static org.easymock.EasyMock.*;
import org.junit.Test;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import java.util.HashMap;
import java.util.Map;


/**
 * @author Les Hazlewood
 * @since Jul 28, 2008 1:34:33 PM
 */
public class SpringShiroFilterTest
{

    @Test
    public void testDefaultConfig() throws Exception {
        SpringShiroFilter filter = new SpringShiroFilter();

        FilterConfig mockConfig = createMock(FilterConfig.class);
        expect(mockConfig.getInitParameter(ShiroFilter.CONFIG_CLASS_NAME_INIT_PARAM_NAME)).andReturn(null);
        expect(mockConfig.getInitParameter(ShiroFilter.CONFIG_INIT_PARAM_NAME)).andReturn(null);
        expect(mockConfig.getInitParameter(ShiroFilter.CONFIG_URL_INIT_PARAM_NAME)).andReturn(null);
        expect(mockConfig.getInitParameter(SpringIniWebConfiguration.SECURITY_MANAGER_BEAN_NAME_PARAM_NAME)).andReturn(null);

        ServletContext mockContext = createMock(ServletContext.class);
        WebApplicationContext appCtx = createMock(WebApplicationContext.class);
        SecurityManager secMgr = createMock(SecurityManager.class);
        Map<String, org.apache.shiro.mgt.SecurityManager> beansOfType = new HashMap<String, SecurityManager>(1);
        beansOfType.put("securityManager", secMgr);

        expect(mockContext.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE)).andReturn(appCtx);
        expect(appCtx.getBeansOfType(SecurityManager.class)).andReturn(beansOfType);

        expect(mockConfig.getServletContext()).andReturn(mockContext).anyTimes();


        replay(mockContext);
        replay(appCtx);
        replay(mockConfig);

        filter.init(mockConfig);
    }
}
