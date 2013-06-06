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
package org.apache.shiro.config.event;

import java.util.Map;

/**
 * Event triggered when a configured bean has been instantiated and fully configured but right before the bean has been
 * initialized.
 *
 * @since 1.3
 * @see InstantiatedBeanEvent
 * @see org.apache.shiro.util.Initializable Initializable
 * @see InitializedBeanEvent
 * @see DestroyedBeanEvent
 */
public class ConfiguredBeanEvent extends BeanEvent {

    public ConfiguredBeanEvent(final String beanName, final Object bean, final Map<String, Object> beanContext) {
        super(beanName, bean, beanContext);
    }
}
