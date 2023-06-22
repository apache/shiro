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
package org.apache.shiro.spring.boot.autoconfigure;

import org.junit.jupiter.api.Test
import org.junit.runner.RunWith
import org.springframework.aop.aspectj.annotation.AnnotationAwareAspectJAutoProxyCreator
import org.springframework.aop.config.AopConfigUtils
import org.springframework.aop.framework.autoproxy.AbstractAdvisorAutoProxyCreator
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator
import org.springframework.beans.BeansException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContext
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner

import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.assertThat

@SpringBootTest(classes = AspectjAndDefaultProxyCreatorApplication.class)
@RunWith(SpringJUnit4ClassRunner.class)
class AspectjAndDefaultProxyCreatorTest {

    @Autowired
    private ApplicationContext applicationContext

    @Test
    void defaultAdvisorAutoProxyCreator() throws BeansException {
        // There are two proxy creators before SHIRO-890 which causes problem when @EnableAspectJAutoProxy is enabled.
        String[] names = ["defaultAdvisorAutoProxyCreator", AopConfigUtils.AUTO_PROXY_CREATOR_BEAN_NAME]
        for (String name : names) {
            Object creator = applicationContext.getBean(name)
            assertThat(creator, anyOf(
                    instanceOf(DefaultAdvisorAutoProxyCreator.class),
                    instanceOf(AnnotationAwareAspectJAutoProxyCreator.class)
            ))
        }
        String[] beanNames = applicationContext.getBeanNamesForType(AbstractAdvisorAutoProxyCreator.class)
        assertThat(names, arrayContainingInAnyOrder(beanNames))
    }
}
