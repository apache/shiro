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
package org.apache.shiro.spring.boot.autoconfigure.web;

import org.apache.shiro.spring.boot.autoconfigure.web.application.ShiroWebAutoConfigurationTestApplication
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager
import org.apache.shiro.web.servlet.AbstractShiroFilter
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.test.context.junit4.SpringRunner

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.instanceOf
import static org.hamcrest.Matchers.nullValue

@RunWith(SpringRunner.class)
@SpringBootTest(classes = [ShiroWebAutoConfigurationTestApplication, Config])
class DisabledGlobalFiltersTest {

    @Configuration
    static class Config {

        @Bean
        List<String> globalFilters() {
            return []
        }
    }

    @Autowired
    private AbstractShiroFilter shiroFilter

    @Test
    void testGlobalFiltersDisabled() {
        // make sure global chains are configured
        assertThat shiroFilter.filterChainResolver.filterChainManager, instanceOf(DefaultFilterChainManager)
        DefaultFilterChainManager filterChainManager = shiroFilter.filterChainResolver.filterChainManager

        // default config set
        assertThat filterChainManager.globalFilterNames, equalTo([])
        // default route configured
        assertThat filterChainManager.getChain("/**"), nullValue()
    }
}
