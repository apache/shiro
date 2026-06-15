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
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import jakarta.servlet.ServletContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class WebGuiceEnvironmentTest {

    @Test
    void ensureInjectable() {
        try {
            InjectionPoint.forConstructorOf(WebGuiceEnvironment.class);
        } catch (Exception e) {
            fail("Could not create constructor injection point.");
        }
    }

    @Test
    void testConstructor() {
        WebSecurityManager securityManager = mock(WebSecurityManager.class);
        FilterChainResolver filterChainResolver = mock(FilterChainResolver.class);
        ServletContext servletContext = mock(ServletContext.class);
        ShiroFilterConfiguration filterConfiguration = mock(ShiroFilterConfiguration.class);

        ArgumentCaptor<WebGuiceEnvironment> capture = ArgumentCaptor.forClass(WebGuiceEnvironment.class);

        WebGuiceEnvironment underTest =
                new WebGuiceEnvironment(filterChainResolver, servletContext, securityManager, filterConfiguration);

        assertThat(underTest.getSecurityManager()).isSameAs(securityManager);
        assertThat(underTest.getFilterChainResolver()).isSameAs(filterChainResolver);
        assertThat(underTest.getWebSecurityManager()).isSameAs(securityManager);
        assertThat(underTest.getServletContext()).isSameAs(servletContext);

        verify(servletContext).setAttribute(eq(EnvironmentLoaderListener.ENVIRONMENT_ATTRIBUTE_KEY), capture.capture());

        assertThat(capture.getValue()).isSameAs(underTest);
    }
}
