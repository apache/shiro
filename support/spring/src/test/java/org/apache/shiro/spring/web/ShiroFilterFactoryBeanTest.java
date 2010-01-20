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
package org.apache.shiro.spring.web;

import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.NamedFilterList;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import javax.servlet.Filter;

import static org.junit.Assert.*;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Jan 19, 2010
 * Time: 4:11:53 PM
 * To change this template use File | Settings | File Templates.
 */
//@RunWith(SpringJUnit4ClassRunner.class)
//@ContextConfiguration(locations = {"/org/apache/shiro/spring/web/ShiroFilterFactoryBeanTest.xml"})
public class ShiroFilterFactoryBeanTest {

    @Test
    public void testFilterDefinition() {

        ClassPathXmlApplicationContext context =
                new ClassPathXmlApplicationContext("org/apache/shiro/spring/web/ShiroFilterFactoryBeanTest.xml");

        AbstractShiroFilter shiroFilter = (AbstractShiroFilter)context.getBean("shiroFilter");

        PathMatchingFilterChainResolver resolver = (PathMatchingFilterChainResolver)shiroFilter.getFilterChainResolver();
        DefaultFilterChainManager fcManager = (DefaultFilterChainManager)resolver.getFilterChainManager();
        NamedFilterList chain = fcManager.getChain("/test");
        assertNotNull(chain);
        assertEquals(chain.size(), 2);
        Filter[] filters = new Filter[chain.size()];
        filters = chain.toArray(filters);
        assertTrue(filters[0] instanceof DummyFilter);
        assertTrue(filters[1] instanceof FormAuthenticationFilter);
    }
}
