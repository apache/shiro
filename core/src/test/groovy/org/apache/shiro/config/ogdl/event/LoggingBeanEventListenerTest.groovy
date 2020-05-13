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
package org.apache.shiro.config.ogdl.event

import org.junit.Test

/**
 * @since 1.3
 */
class LoggingBeanEventListenerTest {

    /**
     * Test that LoggingBeanEventListener attempts to substring class names of BeanEvents that contain the
     * string 'BeanEvent'.
     */
    @Test
    void testMisnamedBeanEventClass() {

        def m = [foo: 'bar'] as Map<String,Object>
        Object o = new Object()
        BeanEvent evt = new MisnamedBean('baz', o, m)

        // This was previously throwing a StringIndexOutOfBoundsException
        new LoggingBeanEventListener().onEvent(evt)
    }

    private class MisnamedBean extends BeanEvent {
        MisnamedBean(String beanName, Object bean, Map<String, Object> beanContext) {
            super(beanName, bean, beanContext)
        }
    }
}
