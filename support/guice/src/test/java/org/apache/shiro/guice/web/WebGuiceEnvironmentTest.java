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

import com.google.inject.spi.InjectionPoint;
import org.apache.shiro.web.config.ShiroFilterConfiguration;
import org.apache.shiro.web.env.EnvironmentLoaderListener;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.easymock.Capture;
import org.junit.Test;

import javax.servlet.ServletContext;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

public class WebGuiceEnvironmentTest {

    @Test
    public void ensureInjectable() {
        try {
            InjectionPoint ip = InjectionPoint.forConstructorOf(WebGuiceEnvironment.class);
        } catch (Exception e) {
            fail("Could not create constructor injection point.");
        }
    }

    @Test
    public void testConstructor() {
        WebSecurityManager securityManager = createMock(WebSecurityManager.class);
        FilterChainResolver filterChainResolver = createMock(FilterChainResolver.class);
        ServletContext servletContext = createMock(ServletContext.class);
        ShiroFilterConfiguration filterConfiguration = createMock(ShiroFilterConfiguration.class);

        Capture<WebGuiceEnvironment> capture = Capture.newInstance();
        servletContext.setAttribute(eq(EnvironmentLoaderListener.ENVIRONMENT_ATTRIBUTE_KEY), and(anyObject(WebGuiceEnvironment.class), capture(capture)));

        replay(servletContext, securityManager, filterChainResolver);

        WebGuiceEnvironment underTest = new WebGuiceEnvironment(filterChainResolver, servletContext, securityManager, filterConfiguration);

        assertSame(securityManager, underTest.getSecurityManager());
        assertSame(filterChainResolver, underTest.getFilterChainResolver());
        assertSame(securityManager, underTest.getWebSecurityManager());
        assertSame(servletContext, underTest.getServletContext());

        assertSame(underTest, capture.getValue());

        verify(servletContext);
    }
}
