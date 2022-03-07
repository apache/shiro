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
package org.apache.shiro.spring.boot.autoconfigure.web

import org.apache.shiro.spring.boot.autoconfigure.web.application.ShiroWebAutoConfigurationTestApplication
import org.apache.shiro.spring.web.ShiroFilterFactoryBean
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration
import org.apache.shiro.web.filter.InvalidRequestFilter
import org.apache.shiro.web.filter.authz.PortFilter
import org.apache.shiro.web.filter.mgt.DefaultFilter
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager
import org.apache.shiro.web.filter.mgt.NamedFilterList
import org.apache.shiro.web.servlet.AbstractShiroFilter
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.test.context.junit4.SpringRunner

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

@RunWith(SpringRunner.class)
@SpringBootTest(classes = [ShiroWebAutoConfigurationTestApplication, Config])

class ConfiguredGlobalFiltersTest {

    @Configuration
    static class Config extends AbstractShiroWebFilterConfiguration {

        @Bean
        List<String> globalFilters() {
            return [DefaultFilter.invalidRequest.name(), DefaultFilter.port.name()]
        }

        @Bean
        @Override
        ShiroFilterFactoryBean shiroFilterFactoryBean() {
            ShiroFilterFactoryBean bean = super.shiroFilterFactoryBean()
            InvalidRequestFilter invalidRequestFilter = new InvalidRequestFilter()
            invalidRequestFilter.setBlockBackslash(false)
            PortFilter portFilter = new PortFilter()
            portFilter.setPort(9999)
            bean.getFilters().put("invalidRequest", invalidRequestFilter)
            bean.getFilters().put("port", portFilter)
            return bean
        }
    }

    @Autowired
    private AbstractShiroFilter shiroFilter

    @Test
    void testGlobalFiltersConfigured() {
        // make sure global chains are configured
        assertThat shiroFilter.filterChainResolver.filterChainManager, instanceOf(DefaultFilterChainManager)
        DefaultFilterChainManager filterChainManager = shiroFilter.filterChainResolver.filterChainManager

        // default config set
        assertThat filterChainManager.globalFilterNames, contains(DefaultFilter.invalidRequest.name(),
                                                                  DefaultFilter.port.name())
        // default route configured
        NamedFilterList allChain = filterChainManager.getChain("/**")
        assertThat allChain, contains(
                instanceOf(DefaultFilter.invalidRequest.filterClass),
                instanceOf(DefaultFilter.port.filterClass))

        InvalidRequestFilter invalidRequest = allChain.get(0)
        assertThat "Expected invalidRequest.blockBackslash to be false", !invalidRequest.isBlockBackslash()
        PortFilter portFilter = allChain.get(1) // an ugly line, but we want to make sure that we can override the filters
        // defined in Shiro's DefaultFilter
        assertThat portFilter.port, equalTo(9999)

        // configured routes also contain global filters
        NamedFilterList loginChain = filterChainManager.getChain("/login.html")
        assertThat loginChain, contains(
                instanceOf(DefaultFilter.invalidRequest.filterClass),
                instanceOf(DefaultFilter.port.filterClass),
                instanceOf(DefaultFilter.authc.filterClass)) // configured in ShiroWebAutoConfigurationTestApplication

        assertThat loginChain.get(0), sameInstance(invalidRequest)
        assertThat loginChain.get(1), sameInstance(portFilter)


    }
}
