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
import com.google.inject.Key;
import com.google.inject.Provides;
import com.google.inject.binder.AnnotatedBindingBuilder;
import com.google.inject.name.Names;
import org.apache.shiro.guice.ShiroModuleTest;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.web.config.ShiroFilterConfiguration;
import org.apache.shiro.web.env.EnvironmentLoader;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.InvalidRequestFilter;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter;
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.easymock.EasyMock;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import jakarta.inject.Named;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;


public class ShiroWebModuleTest {


    @Test
    void basicInstantiation() {
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
        // expose it outside the Shiro module.
        SecurityManager securityManager = injector.getInstance(SecurityManager.class);
        assertThat(securityManager).isNotNull();
        assertThat(securityManager instanceof WebSecurityManager).isTrue();
        SessionManager sessionManager = injector.getInstance(SessionManager.class);
        assertThat(sessionManager).isNotNull();
        assertThat(sessionManager instanceof ServletContainerSessionManager).isTrue();
        assertThat(((DefaultWebSecurityManager) securityManager).getSessionManager())
            .isInstanceOf(ServletContainerSessionManager.class);
    }

    @Test
    void testBindGuiceFilter() throws Exception {

    }

    @Test
    void testBindWebSecurityManager() throws Exception {
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
                bind.to(MyDefaultWebSecurityManager.class).asEagerSingleton();
            }
        });
        SecurityManager securityManager = injector.getInstance(SecurityManager.class);
        assertThat(securityManager).isNotNull();
        assertThat(securityManager instanceof MyDefaultWebSecurityManager).isTrue();
        WebSecurityManager webSecurityManager = injector.getInstance(WebSecurityManager.class);
        assertThat(webSecurityManager).isNotNull();
        assertThat(webSecurityManager instanceof MyDefaultWebSecurityManager).isTrue();
        // SHIRO-435: Check both keys SecurityManager and WebSecurityManager are bound to the same instance
        assertThat(securityManager == webSecurityManager).isTrue();
    }

    @Test
    void testBindWebEnvironment() throws Exception {
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
                bind.to(MyWebEnvironment.class).asEagerSingleton();
            }
        });
        Environment environment = injector.getInstance(Environment.class);
        assertThat(environment).isNotNull();
        assertThat(environment instanceof MyWebEnvironment).isTrue();
        WebEnvironment webEnvironment = injector.getInstance(WebEnvironment.class);
        assertThat(webEnvironment).isNotNull();
        assertThat(webEnvironment instanceof MyWebEnvironment).isTrue();
        // SHIRO-435: Check both keys Environment and WebEnvironment are bound to the same instance
        assertThat(environment == webEnvironment).isTrue();
    }

    /**
     * @since 1.4
     */
    @SuppressWarnings("checkstyle:MethodLength")
    @Test
    void testAddFilterChainGuice3and4() {

        final ShiroModuleTest.MockRealm mockRealm = createMock(ShiroModuleTest.MockRealm.class);
        ServletContext servletContext = createMock(ServletContext.class);
        HttpServletRequest request = createMock(HttpServletRequest.class);

        servletContext.setAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY), EasyMock.anyObject());
        expect(request.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH)).andReturn("").anyTimes();
        expect(request.getCharacterEncoding()).andReturn("UTF-8").anyTimes();
        expect(request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO)).andReturn(null).anyTimes();
        expect(request.getPathInfo()).andReturn(null).anyTimes();
        expect(request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH)).andReturn("/test_authc");
        expect(request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH)).andReturn("/test_custom_filter");
        expect(request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH)).andReturn("/test_authc_basic");
        expect(request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH)).andReturn("/test_perms");
        expect(request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH)).andReturn("/multiple_configs");
        replay(servletContext, request);

        Injector injector = Guice.createInjector(new ShiroWebModule(servletContext) {
            @Override
            protected void configureShiroWeb() {
                bindRealm().to(ShiroModuleTest.MockRealm.class);
                expose(FilterChainResolver.class);
                this.addFilterChain("/test_authc/**", filterConfig(AUTHC));
                this.addFilterChain("/test_custom_filter/**", Key.get(CustomFilter.class));
                this.addFilterChain("/test_authc_basic/**", AUTHC_BASIC);
                this.addFilterChain("/test_perms/**", filterConfig(PERMS, "remote:invoke:lan,wan"));
                this.addFilterChain("/multiple_configs/**", filterConfig(AUTHC), filterConfig(ROLES, "b2bClient"),
                        filterConfig(PERMS, "remote:invoke:lan,wan"));
            }

            @Provides
            public ShiroModuleTest.MockRealm createRealm() {
                return mockRealm;
            }
        });

        FilterChainResolver resolver = injector.getInstance(FilterChainResolver.class);
        assertThat(resolver).isInstanceOf(SimpleFilterChainResolver.class);
        SimpleFilterChainResolver simpleFilterChainResolver = (SimpleFilterChainResolver) resolver;

        // test the /test_authc resource
        FilterChain filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);
        Filter nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(InvalidRequestFilter.class);
        nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(FormAuthenticationFilter.class);

        // test the /test_custom_filter resource
        filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);
        nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(InvalidRequestFilter.class);
        nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(CustomFilter.class);

        // test the /test_authc_basic resource
        filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);
        nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(InvalidRequestFilter.class);
        nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(BasicHttpAuthenticationFilter.class);

        // test the /test_perms resource
        filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);
        nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(InvalidRequestFilter.class);
        nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(PermissionsAuthorizationFilter.class);

        // test the /multiple_configs resource
        filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isInstanceOf(InvalidRequestFilter.class);
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isInstanceOf(FormAuthenticationFilter.class);
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isInstanceOf(RolesAuthorizationFilter.class);
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isInstanceOf(PermissionsAuthorizationFilter.class);

        verify(servletContext, request);
    }

    /**
     * @since 1.4
     */
    @Test
    @Tag("Guice3")
    void testAddFilterChainGuice3Only() {

        Assumptions.assumeTrue(ShiroWebModule.isGuiceVersion3(), "This test only runs against Guice 3.x");

        final ShiroModuleTest.MockRealm mockRealm = createMock(ShiroModuleTest.MockRealm.class);
        ServletContext servletContext = createMock(ServletContext.class);
        HttpServletRequest request = createMock(HttpServletRequest.class);

        servletContext.setAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY), EasyMock.anyObject());
        expect(request.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH)).andReturn("").anyTimes();
        expect(request.getCharacterEncoding()).andReturn("UTF-8").anyTimes();
        expect(request.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH)).andReturn("/test_authc");
        expect(request.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH)).andReturn("/test_custom_filter");
        expect(request.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH)).andReturn("/test_perms");
        expect(request.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH)).andReturn("/multiple_configs");
        replay(servletContext, request);

        Injector injector = Guice.createInjector(new ShiroWebModule(servletContext) {

            @Override
            @SuppressWarnings("unchecked")
            @Deprecated
            protected void configureShiroWeb() {
                bindRealm().to(ShiroModuleTest.MockRealm.class);
                expose(FilterChainResolver.class);
                this.addFilterChain("/test_authc/**", AUTHC);
                this.addFilterChain("/test_custom_filter/**", Key.get(CustomFilter.class));
                this.addFilterChain("/test_perms/**", config(PERMS, "remote:invoke:lan,wan"));
                this.addFilterChain("/multiple_configs/**",
                                            AUTHC,
                                            config(ROLES, "b2bClient"),
                                            config(PERMS, "remote:invoke:lan,wan"));
            }

            @Provides
            public ShiroModuleTest.MockRealm createRealm() {
                return mockRealm;
            }
        });

        FilterChainResolver resolver = injector.getInstance(FilterChainResolver.class);
        assertThat(resolver).isInstanceOf(SimpleFilterChainResolver.class);
        SimpleFilterChainResolver simpleFilterChainResolver = (SimpleFilterChainResolver) resolver;

        // test the /test_authc resource
        FilterChain filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);
        Filter nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(FormAuthenticationFilter.class);

        // test the /test_custom_filter resource
        filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);
        nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(CustomFilter.class);

        // test the /test_perms resource
        filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);
        nextFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(nextFilter).isInstanceOf(PermissionsAuthorizationFilter.class);

        // test the /multiple_configs resource
        filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isInstanceOf(FormAuthenticationFilter.class);
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isInstanceOf(RolesAuthorizationFilter.class);
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isInstanceOf(PermissionsAuthorizationFilter.class);

        verify(servletContext, request);
    }

    @Test
    void testDefaultPath() {

        final ShiroModuleTest.MockRealm mockRealm = createMock(ShiroModuleTest.MockRealm.class);
        ServletContext servletContext = createMock(ServletContext.class);
        HttpServletRequest request = createMock(HttpServletRequest.class);

        servletContext.setAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY), EasyMock.anyObject());
        expect(request.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH)).andReturn("").anyTimes();
        expect(request.getCharacterEncoding()).andReturn("UTF-8").anyTimes();
        expect(request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO)).andReturn(null).anyTimes();
        expect(request.getPathInfo()).andReturn(null).anyTimes();
        expect(request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH)).andReturn("/test/foobar");
        replay(servletContext, request);

        Injector injector = Guice.createInjector(new ShiroWebModule(servletContext) {
            @Override
            protected void configureShiroWeb() {
                bindRealm().to(ShiroModuleTest.MockRealm.class);
                expose(FilterChainResolver.class);
                // no paths configured
            }

            @Provides
            public ShiroModuleTest.MockRealm createRealm() {
                return mockRealm;
            }
        });

        FilterChainResolver resolver = injector.getInstance(FilterChainResolver.class);
        assertThat(resolver).isInstanceOf(SimpleFilterChainResolver.class);
        SimpleFilterChainResolver simpleFilterChainResolver = (SimpleFilterChainResolver) resolver;

        // test the /test_authc resource
        FilterChain filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);

        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isInstanceOf(InvalidRequestFilter.class);
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isNull();

        verify(servletContext, request);
    }

    @Test
    void testDisableGlobalFilters() {

        final ShiroModuleTest.MockRealm mockRealm = createMock(ShiroModuleTest.MockRealm.class);
        ServletContext servletContext = createMock(ServletContext.class);
        HttpServletRequest request = createMock(HttpServletRequest.class);

        servletContext.setAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY), EasyMock.anyObject());
        expect(request.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH)).andReturn("").anyTimes();
        expect(request.getCharacterEncoding()).andReturn("UTF-8").anyTimes();
        expect(request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO)).andReturn(null).anyTimes();
        expect(request.getPathInfo()).andReturn(null).anyTimes();
        expect(request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH)).andReturn("/test/foobar");
        replay(servletContext, request);

        Injector injector = Guice.createInjector(new ShiroWebModule(servletContext) {
            @Override
            protected void configureShiroWeb() {
                bindRealm().to(ShiroModuleTest.MockRealm.class);
                expose(FilterChainResolver.class);
                this.addFilterChain("/**", filterConfig(AUTHC));
            }

            @Override
            public List<FilterConfig<? extends Filter>> globalFilters() {
                return Collections.emptyList();
            }

            @Provides
            public ShiroModuleTest.MockRealm createRealm() {
                return mockRealm;
            }
        });

        FilterChainResolver resolver = injector.getInstance(FilterChainResolver.class);
        assertThat(resolver).isInstanceOf(SimpleFilterChainResolver.class);
        SimpleFilterChainResolver simpleFilterChainResolver = (SimpleFilterChainResolver) resolver;

        // test the /test_authc resource
        FilterChain filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);

        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isInstanceOf(FormAuthenticationFilter.class);
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isNull();

        verify(servletContext, request);
    }

    @Test
    void testChangeInvalidFilterConfig() {

        final ShiroModuleTest.MockRealm mockRealm = createMock(ShiroModuleTest.MockRealm.class);
        ServletContext servletContext = createMock(ServletContext.class);
        HttpServletRequest request = createMock(HttpServletRequest.class);

        servletContext.setAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY), EasyMock.anyObject());
        expect(request.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH)).andReturn("").anyTimes();
        expect(request.getCharacterEncoding()).andReturn("UTF-8").anyTimes();
        expect(request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO)).andReturn(null).anyTimes();
        expect(request.getPathInfo()).andReturn(null).anyTimes();
        expect(request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH)).andReturn("/test/foobar");
        replay(servletContext, request);

        Injector injector = Guice.createInjector(new ShiroWebModule(servletContext) {
            @Override
            protected void configureShiroWeb() {

                bindConstant().annotatedWith(Names.named("shiro.blockBackslash")).to(false);

                bindRealm().to(ShiroModuleTest.MockRealm.class);
                expose(FilterChainResolver.class);
                this.addFilterChain("/**", filterConfig(AUTHC));
            }

            @Provides
            public ShiroModuleTest.MockRealm createRealm() {
                return mockRealm;
            }
        });

        FilterChainResolver resolver = injector.getInstance(FilterChainResolver.class);
        assertThat(resolver).isInstanceOf(SimpleFilterChainResolver.class);
        SimpleFilterChainResolver simpleFilterChainResolver = (SimpleFilterChainResolver) resolver;

        // test the /test_authc resource
        FilterChain filterChain = simpleFilterChainResolver.getChain(request, null, null);
        assertThat(filterChain).isInstanceOf(SimpleFilterChain.class);

        Filter invalidRequestFilter = getNextFilter((SimpleFilterChain) filterChain);
        assertThat(invalidRequestFilter).isInstanceOf(InvalidRequestFilter.class);
        assertThat(((InvalidRequestFilter) invalidRequestFilter).isBlockBackslash())
                .as("Expected 'blockBackslash' to be false")
                .isFalse();
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isInstanceOf(FormAuthenticationFilter.class);
        assertThat(getNextFilter((SimpleFilterChain) filterChain)).isNull();

        verify(servletContext, request);
    }

    private Filter getNextFilter(SimpleFilterChain filterChain) {

        Iterator<? extends Filter> filters = filterChain.getFilters();
        if (filters.hasNext()) {
            return filters.next();
        }

        return null;
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
        MyWebEnvironment(FilterChainResolver filterChainResolver, @Named(ShiroWebModule.NAME) ServletContext servletContext,
                         WebSecurityManager securityManager, ShiroFilterConfiguration filterConfiguration) {
            super(filterChainResolver, servletContext, securityManager, filterConfiguration);
        }
    }

    public static class CustomFilter implements Filter {

        @Override
        public void init(FilterConfig filterConfig) throws ServletException {
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
        }

        @Override
        public void destroy() {
        }
    }
}
