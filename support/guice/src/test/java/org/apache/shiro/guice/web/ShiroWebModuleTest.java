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
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Provides;
import com.google.inject.binder.AnnotatedBindingBuilder;
import org.apache.shiro.guice.ShiroModuleTest;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.junit.Test;

import javax.inject.Named;
import javax.servlet.ServletContext;
import java.util.Collection;

import static org.easymock.EasyMock.createMock;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ShiroWebModuleTest {


    @Test
    public void basicInstantiation() {
        final ShiroModuleTest.MockRealm mockRealm = createMock(ShiroModuleTest.MockRealm.class);
        ServletContext servletContext = createMock(ServletContext.class);

        Injector injector = Guice.createInjector(new ShiroWebModule(servletContext) {
            @Override
            protected void configureShiroWeb() {
                bindRealm().to(ShiroModuleTest.MockRealm.class);
                expose(SessionManager.class);
            }

            @Provides
            public ShiroModuleTest.MockRealm createRealm() {
                return mockRealm;
            }

        });
        // we're not getting a WebSecurityManager here b/c it's not exposed.  There didn't seem to be a good reason to
        // expose it outside of the Shiro module.
        SecurityManager securityManager = injector.getInstance(SecurityManager.class);
        assertNotNull(securityManager);
        assertTrue(securityManager instanceof WebSecurityManager);
        SessionManager sessionManager = injector.getInstance(SessionManager.class);
        assertNotNull(sessionManager);
        assertTrue(sessionManager instanceof DefaultWebSessionManager);
        assertTrue(((DefaultWebSecurityManager)securityManager).getSessionManager() instanceof DefaultWebSessionManager);
    }

    @Test
    public void testBindGuiceFilter() throws Exception {

    }

    @Test
    public void testBindWebSecurityManager() throws Exception {
        final ShiroModuleTest.MockRealm mockRealm = createMock(ShiroModuleTest.MockRealm.class);
        ServletContext servletContext = createMock(ServletContext.class);

        Injector injector = Guice.createInjector(new ShiroWebModule(servletContext) {
            @Override
            protected void configureShiroWeb() {
                bindRealm().to(ShiroModuleTest.MockRealm.class);
                expose(WebSecurityManager.class);
            }

            @Provides
            public ShiroModuleTest.MockRealm createRealm() {
                return mockRealm;
            }

            @Override
            protected void bindWebSecurityManager(AnnotatedBindingBuilder<? super WebSecurityManager> bind) {
                bind.to(MyDefaultWebSecurityManager.class);
            }
        });
        SecurityManager securityManager = injector.getInstance(SecurityManager.class);
        assertNotNull(securityManager);
        assertTrue(securityManager instanceof MyDefaultWebSecurityManager);
        WebSecurityManager webSecurityManager = injector.getInstance(WebSecurityManager.class);
        assertNotNull(webSecurityManager);
        assertTrue(webSecurityManager instanceof MyDefaultWebSecurityManager);

    }

    @Test
    public void testBindWebEnvironment() throws Exception {
        final ShiroModuleTest.MockRealm mockRealm = createMock(ShiroModuleTest.MockRealm.class);
        ServletContext servletContext = createMock(ServletContext.class);

        Injector injector = Guice.createInjector(new ShiroWebModule(servletContext) {
            @Override
            protected void configureShiroWeb() {
                bindRealm().to(ShiroModuleTest.MockRealm.class);
                expose(WebEnvironment.class);
                expose(Environment.class);
            }

            @Provides
            public ShiroModuleTest.MockRealm createRealm() {
                return mockRealm;
            }

            @Override
            protected void bindWebEnvironment(AnnotatedBindingBuilder<? super WebEnvironment> bind) {
                bind.to(MyWebEnvironment.class);
            }
        });
        Environment environment = injector.getInstance(Environment.class);
        assertNotNull(environment);
        assertTrue(environment instanceof MyWebEnvironment);
        WebEnvironment webEnvironment = injector.getInstance(WebEnvironment.class);
        assertNotNull(webEnvironment);
        assertTrue(webEnvironment instanceof MyWebEnvironment);
    }

    public static class MyDefaultWebSecurityManager extends DefaultWebSecurityManager {
        @Inject
        public MyDefaultWebSecurityManager(Collection<Realm> realms) {
            super(realms);
        }
    }

    public static class MyDefaultWebSessionManager extends DefaultWebSessionManager {
    }

    public static class MyWebEnvironment extends WebGuiceEnvironment {
        @Inject
        MyWebEnvironment(FilterChainResolver filterChainResolver, @Named(ShiroWebModule.NAME) ServletContext servletContext, WebSecurityManager securityManager) {
            super(filterChainResolver, servletContext, securityManager);
        }
    }
}
