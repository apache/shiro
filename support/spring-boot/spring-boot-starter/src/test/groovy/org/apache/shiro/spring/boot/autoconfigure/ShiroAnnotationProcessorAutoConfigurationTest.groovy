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
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.aop.aspectj.annotation.AnnotationAwareAspectJAutoProxyCreator
import org.springframework.aop.config.AopConfigUtils
import org.springframework.aop.framework.autoproxy.AbstractAdvisorAutoProxyCreator
import org.springframework.beans.BeansException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContext
import org.springframework.test.context.junit.jupiter.SpringExtension

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

@SpringBootTest(classes = AspectjEnabledApplication.class)
@ExtendWith(SpringExtension.class)
class ShiroAnnotationProcessorAutoConfigurationTest {

    @Autowired
    private ApplicationContext applicationContext

    @Test
    void defaultAdvisorAutoProxyCreator() throws BeansException {
        //  There is only one proxy creator, and it's AnnotationAwareAspectJAutoProxyCreator as expected.
        Object creator = applicationContext.getBean(AopConfigUtils.AUTO_PROXY_CREATOR_BEAN_NAME)
        assertThat("@EnableAspectJAutoProxy will create an instance of AnnotationAwareAspectJAutoProxyCreator",
                creator, instanceOf(AnnotationAwareAspectJAutoProxyCreator.class))
        String[] names = applicationContext.getBeanNamesForType(AbstractAdvisorAutoProxyCreator.class)
        assertThat(names, arrayWithSize(1))
    }
}
