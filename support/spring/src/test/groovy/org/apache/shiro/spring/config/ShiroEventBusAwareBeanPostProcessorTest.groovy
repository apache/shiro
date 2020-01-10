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
package org.apache.shiro.spring.config

import org.apache.shiro.event.EventBus
import org.apache.shiro.event.EventBusAware
import org.apache.shiro.spring.ShiroEventBusBeanPostProcessor
import org.junit.Assert
import org.junit.Test

import static org.mockito.Mockito.mock

/**
 * Tests for {@link org.apache.shiro.spring.ShiroEventBusBeanPostProcessor}
 */
class ShiroEventBusAwareBeanPostProcessorTest {

    @Test
    void testPostConstructNonAware() {

        def eventBus = mock(EventBus)
        def bean = mock(Object)

        def postProcessor = new ShiroEventBusBeanPostProcessor(eventBus);
        def resultAfter = postProcessor.postProcessAfterInitialization(bean, "bean")
        def resultBefore = postProcessor.postProcessBeforeInitialization(bean, "bean")

        Assert.assertSame resultAfter, bean
        Assert.assertSame resultBefore, bean
    }

    @Test
    void testPostConstructWithEventBusAware() {

        def eventBus = mock(EventBus)
        def bean = mock(EventBusAware)
        bean.eventBus = eventBus

        def postProcessor = new ShiroEventBusBeanPostProcessor(eventBus);
        def resultAfter = postProcessor.postProcessAfterInitialization(bean, "bean")
        def resultBefore = postProcessor.postProcessBeforeInitialization(bean, "bean")

        Assert.assertSame resultAfter, bean
        Assert.assertSame resultBefore, bean
    }

}
