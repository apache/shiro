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

import org.apache.shiro.event.Subscribe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A stock bean listener implementation that logs all BeanEvents via the standard logging mechanism.
 *
 * @since 1.3
 */
public class LoggingBeanListener {

    private static final Logger logger = LoggerFactory.getLogger(LoggingBeanListener.class);

    @Subscribe
    protected void onUnhandledBeanEvent(BeanEvent beanEvent) {
        logger.warn("UNHANDLED EVENT :: {} :: {}", beanEvent.getBeanName(), beanEvent.getBean());
    }

    @Subscribe
    protected void onInstantiatedBeanEvent(InstantiatedBeanEvent beanEvent) {
        logger.info("INSTANTIATED :: {} :: {}", beanEvent.getBeanName(), beanEvent.getBean());
    }

    @Subscribe
    protected void onConfiguredBeanEvent(ConfiguredBeanEvent beanEvent) {
        logger.info("CONFIGURED :: {} :: {}", beanEvent.getBeanName(), beanEvent.getBean());
    }

    @Subscribe
    protected void onDestroyedBeanEvent(DestroyedBeanEvent beanEvent) {
        logger.info("DESTROYED :: {} :: {}", beanEvent.getBeanName(), beanEvent.getBean());
    }
}
