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
package org.apache.shiro.config;

import org.apache.shiro.config.event.BeanEvent;
import org.apache.shiro.config.event.ConfiguredBeanEvent;
import org.apache.shiro.config.event.DestroyedBeanEvent;
import org.apache.shiro.config.event.InstantiatedBeanEvent;
import org.apache.shiro.event.Subscribe;

import java.util.ArrayList;
import java.util.List;

/**
 * @since 1.3
 */
public class RecordingBeanListener {

    private List<InstantiatedBeanEvent> instantiateEvents = new ArrayList<InstantiatedBeanEvent>();
    private List<ConfiguredBeanEvent> configuredEvents = new ArrayList<ConfiguredBeanEvent>();
    private List<DestroyedBeanEvent> destroyedEvents = new ArrayList<DestroyedBeanEvent>();
    private List<BeanEvent> unhandledEvents = new ArrayList<BeanEvent>();

    @Subscribe
    protected void onUnhandledBeanEvent(BeanEvent beanEvent) {
        this.unhandledEvents.add(beanEvent);
    }

    @Subscribe
    protected void onInstantiatedBeanEvent(InstantiatedBeanEvent beanEvent) {
        this.instantiateEvents.add(beanEvent);
    }

    @Subscribe
    protected void onConfiguredBeanEvent(ConfiguredBeanEvent beanEvent) {
        this.configuredEvents.add(beanEvent);
    }

    @Subscribe
    protected void onDestroyedBeanEvent(DestroyedBeanEvent beanEvent) {
        this.destroyedEvents.add(beanEvent);
    }

    public List<InstantiatedBeanEvent> getInstantiateEvents() {
        return instantiateEvents;
    }

    public List<ConfiguredBeanEvent> getConfiguredEvents() {
        return configuredEvents;
    }

    public List<DestroyedBeanEvent> getDestroyedEvents() {
        return destroyedEvents;
    }

    public List<BeanEvent> getUnhandledEvents() {
        return unhandledEvents;
    }
}
