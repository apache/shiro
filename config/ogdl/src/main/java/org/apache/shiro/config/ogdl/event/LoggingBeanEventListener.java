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
package org.apache.shiro.config.ogdl.event;

import org.apache.shiro.event.Subscribe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A stock bean listener implementation that logs all BeanEvents as TRACE log statements.
 *
 * @since 1.3
 */
public class LoggingBeanEventListener {

    private static final Logger logger = LoggerFactory.getLogger(LoggingBeanEventListener.class);
    private static final String SUFFIX = BeanEvent.class.getSimpleName();

    @Subscribe
    public void onEvent(BeanEvent e) {
        String className = e.getClass().getSimpleName();
        int i = className.lastIndexOf(SUFFIX);
        String subclassPrefix = i > 0 ? className.substring(0, i) : className;
        logger.trace("{} bean '{}' [{}]", new Object[]{subclassPrefix, e.getBeanName(), e.getBean()});
    }
}
