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
package org.apache.shiro.spring.config.web.autoconfigure;

import jakarta.servlet.Filter;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.apache.shiro.spring.web.SpringPathPatternMatcher;
import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.webmvc.autoconfigure.WebMvcProperties;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.util.pattern.PatternParseException;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.Map;
import java.util.Arrays;
import java.util.LinkedHashMap;
import static org.apache.shiro.spring.config.web.autoconfigure.ShiroEnvironmentPostProcessor.ANT_PATH_MATCHER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ShiroPathMatchingTest {

    @Test
    void preservesLegacyPostProcessorAndMatcher() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        new ShiroEnvironmentPostProcessor().postProcessEnvironment(environment, new SpringApplication());
        boolean antSupported = Arrays.stream(WebMvcProperties.MatchingStrategy.values())
                .anyMatch(strategy -> strategy.name().equalsIgnoreCase(ANT_PATH_MATCHER));
        assertThat(environment.getProperty("spring.mvc.pathmatch.matching-strategy"))
                .isEqualTo(antSupported ? ANT_PATH_MATCHER : null);
        TestConfiguration configuration = new TestConfiguration("/users/*", null);
        assertThat(resolver(configuration).getPathMatcher()).isInstanceOf(AntPathMatcher.class);
    }

    @Test
    void usesSpringPatternsWhenMvcDidNotApplyAntSetting() throws Exception {
        TestConfiguration configuration = new TestConfiguration("/users/{id}", new PathPatternParser());
        PathMatchingFilterChainResolver resolver = resolver(configuration);
        assertThat(resolver.getPathMatcher()).isInstanceOf(SpringPathPatternMatcher.class);
        assertThat(resolver.isCaseInsensitive()).isTrue();
        MockHttpServletRequest request = request("/users/42");
        MockHttpServletResponse response = new MockHttpServletResponse();
        resolver.getChain(request, response, (req, res) -> { }).doFilter(request, response);
        assertThat(configuration.probe.matches).isEqualTo(1);

        DefaultFilterChainManager manager = (DefaultFilterChainManager) resolver.getFilterChainManager();
        manager.getFilterChains().remove("/**");
        assertThat(resolver.getChain(request("/users/42/"), response, (req, res) -> { })).isNotNull();
        assertThat(resolver.getChain(request("/Users/42"), response, (req, res) -> { })).isNotNull();
        configuration.probe.doFilter(request("/users/42/"), response, (req, res) -> { });
        assertThat(configuration.probe.matches).isEqualTo(2);
    }

    @Test
    void preservesTrailingSlashProtectionBeforeAnonymousFallback() throws Exception {
        for (PathPatternParser parser : new PathPatternParser[]{null, new PathPatternParser()}) {
            String userPattern = parser == null ? "/users/*" : "/users/{id}";
            for (String pattern : new String[]{"/admin", "/admin/", userPattern, userPattern + "/", "/files/**"}) {
                Map<String, String> chains = new LinkedHashMap<>();
                chains.put(pattern, "probe");
                chains.put("/**", "anon");
                TestConfiguration configuration = new TestConfiguration(chains, parser);
                PathMatchingFilterChainResolver resolver = resolver(configuration);
                String path = pattern.replace("{id}", "42").replace("**", "private/report.pdf").replace("*", "42");
                String alternate = path.endsWith("/") ? path.substring(0, path.length() - 1) : path + "/";
                for (String requestPath : new String[]{path, alternate}) {
                    MockHttpServletRequest request = request(requestPath);
                    boolean[] resourceServed = {false};
                    resolver.getChain(request, new MockHttpServletResponse(), (req, res) -> resourceServed[0] = true)
                            .doFilter(request, new MockHttpServletResponse());
                    assertThat(resourceServed[0]).as("%s against %s", pattern, requestPath).isFalse();
                }
                assertThat(configuration.probe.matches).as("filter execution for %s", pattern).isEqualTo(2);
            }
        }
    }

    @Test
    void rejectsInvalidSpringPatternsDuringConfiguration() {
        assertThatThrownBy(() -> new TestConfiguration("/users/{id", new PathPatternParser()).shiroFilterFactoryBean())
                .isInstanceOf(PatternParseException.class);
    }

    @Test
    void honorsExplicitCaseSensitivity() throws Exception {
        PathPatternParser parser = new PathPatternParser();
        parser.setCaseSensitive(false);
        TestConfiguration configuration = new TestConfiguration(Map.of("/users/{id}", "probe"), parser, false);
        PathMatchingFilterChainResolver resolver = resolver(configuration);
        assertThat(resolver.isCaseInsensitive()).isFalse();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = request("/users/42");
        resolver.getChain(request, response, (req, res) -> { }).doFilter(request, response);
        assertThat(configuration.probe.matches).isEqualTo(1);
        DefaultFilterChainManager manager = (DefaultFilterChainManager) resolver.getFilterChainManager();
        manager.getFilterChains().remove("/**");
        assertThat(resolver.getChain(request("/Users/42"), response, (req, res) -> { })).isNull();
        configuration.probe.doFilter(request("/Users/42"), response, (req, res) -> { });
        assertThat(configuration.probe.matches).isEqualTo(1);
    }

    @Test
    void protectsMixedCaseStaticPathsBeforeAnonymousFallback() throws Exception {
        Map<String, String> chains = new LinkedHashMap<>();
        chains.put("/files/private/**", "probe");
        chains.put("/files/**", "anon");
        TestConfiguration configuration = new TestConfiguration(chains, new PathPatternParser());
        PathMatchingFilterChainResolver resolver = resolver(configuration);
        MockHttpServletRequest request = request("/files/PRIVATE/report.pdf");
        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] resourceServed = {false};
        resolver.getChain(request, response, (req, res) -> resourceServed[0] = true).doFilter(request, response);
        assertThat(configuration.probe.matches).isEqualTo(1);
        assertThat(resourceServed[0]).isFalse();
    }

    private static PathMatchingFilterChainResolver resolver(TestConfiguration configuration) throws Exception {
        AbstractShiroFilter filter = (AbstractShiroFilter) configuration.shiroFilterFactoryBean().getObject();
        return (PathMatchingFilterChainResolver) filter.getFilterChainResolver();
    }

    private static MockHttpServletRequest request(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath(path);
        return request;
    }

    private static class TestConfiguration extends ShiroWebFilterConfiguration {
        private final ProbeFilter probe = new ProbeFilter();

        TestConfiguration(String pattern, PathPatternParser parser) {
            this(Map.of(pattern, "probe"), parser);
        }

        TestConfiguration(Map<String, String> chains, PathPatternParser parser) {
            this(chains, parser, true);
        }

        TestConfiguration(Map<String, String> chains, PathPatternParser parser, boolean ignoreCase) {
            securityManager = new DefaultWebSecurityManager();
            shiroFilterChainDefinition = () -> chains;
            caseInsensitive = ignoreCase;
            RequestMappingHandlerMapping mapping = new RequestMappingHandlerMapping();
            mapping.setPatternParser(parser);
            DefaultListableBeanFactory factory = new DefaultListableBeanFactory();
            factory.registerSingleton("requestMappingHandlerMapping", mapping);
            handlerMappings = factory.getBeanProvider(RequestMappingHandlerMapping.class);
        }

        @Override
        protected Map<String, Filter> filterMap() {
            return Map.of("probe", probe);
        }
    }

    private static final class ProbeFilter extends PathMatchingFilter {
        private int matches;

        @Override
        protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) {
            matches++;
            return false;
        }
    }
}
