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
package org.apache.shiro.guice.web;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Provides;
import org.apache.shiro.guice.ShiroModuleTest;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.util.WebUtils;
import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertNotNull;

public class FilterConfigTest {
    private FilterChainResolver setupResolver() {
        final ShiroModuleTest.MockRealm mockRealm = createMock(ShiroModuleTest.MockRealm.class);
        ServletContext servletContext = createMock(ServletContext.class);

        Injector injector = Guice.createInjector(new ShiroWebModule(servletContext) {
            @Override
            protected void configureShiroWeb() {
                bindRealm().to(ShiroModuleTest.MockRealm.class);

                addFilterChain("/index.html", AUTHC_BASIC);
//                addFilterChain("/index2.html", config(PERMS, "permission"));
                addFilterChain("/index2.html", filterConfig(PERMS, "permission"));
            }

            @Provides
            public ShiroModuleTest.MockRealm createRealm() {
                return mockRealm;
            }
        });
        GuiceShiroFilter filter = injector.getInstance(GuiceShiroFilter.class);
        return filter.getFilterChainResolver();
    }

    @Test
    public void testSimple() throws Exception {
        FilterChainResolver resolver = setupResolver();
        HttpServletResponse response = createNiceMock(HttpServletResponse.class);
        FilterChain chain = createNiceMock(FilterChain.class);
        HttpServletRequest request = createMockRequest("/index.html");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request);
    }

    @Test
    public void testWithConfig() throws Exception {
        FilterChainResolver resolver = setupResolver();
        HttpServletResponse response = createNiceMock(HttpServletResponse.class);
        FilterChain chain = createNiceMock(FilterChain.class);
        HttpServletRequest request = createMockRequest("/index2.html");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request);
    }

    private HttpServletRequest createMockRequest(String path) {
        HttpServletRequest request = createNiceMock(HttpServletRequest.class);

        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null).anyTimes();
        expect(request.getContextPath()).andReturn("");
        expect(request.getPathInfo()).andReturn(path);
        replay(request);
        return request;
    }

}
