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
package org.apache.shiro.event;

/**
 * Interface implemented by components that utilize an EventBus for publishing and/or subscribing to/from events
 * and wish that EventBus to be supplied if one is available.
 * <p/>
 * <b>NOTE:</b> If an {@code EventBusAware} implementation wishes to subscribe to events (i.e. it has
 * {@code @Subscriber}-annotated methods itself, it must register itself with the event bus, i.e.:
 * <pre>
 * eventBus.register(this);
 * </pre>
 * Shiro's default configuration mechanisms will <em>NOT</em> auto-register {@code @Subscriber}-annotated components
 * that are also {@code EventBusAware}: it is assumed that the {@code EventBusAware} implementation, having access to
 * an EventBus directly, knows best when to register/unregister itself.
 *
 * @since 1.3
 */
public interface EventBusAware {

    /**
     * Sets the available {@code EventBus} that may be used for publishing and subscribing to/from events.
     *
     * @param bus the available {@code EventBus}.
     */
    void setEventBus(EventBus bus);
}
