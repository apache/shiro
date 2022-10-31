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
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.junit.Test;

import static org.mockito.Mockito.mock;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.when;

public class GuiceShiroFilterTest {

    @Test
    public void ensureInjectable() {
        try {
            InjectionPoint.forConstructorOf(GuiceShiroFilter.class);
        } catch (Exception e) {
            fail("Could not create constructor injection point.");
        }
    }

    @Test
    public void testConstructor() {
        WebSecurityManager securityManager = mock(WebSecurityManager.class);
        FilterChainResolver filterChainResolver = mock(FilterChainResolver.class);
        ShiroFilterConfiguration filterConfiguration = mock(ShiroFilterConfiguration.class);
        when(filterConfiguration.isStaticSecurityManagerEnabled()).thenReturn(true);
        when(filterConfiguration.isFilterOncePerRequest()).thenReturn(false);

        GuiceShiroFilter underTest = new GuiceShiroFilter(securityManager, filterChainResolver, filterConfiguration);

        assertSame(securityManager, underTest.getSecurityManager());
        assertSame(filterChainResolver, underTest.getFilterChainResolver());
        assertTrue(underTest.isStaticSecurityManagerEnabled());
        assertFalse(underTest.isFilterOncePerRequest());
    }
}
