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
package org.apache.shiro.event.bus;

/**
 * Allows event subscribers to register or unregister with an event subsystem to receive (or not receive) published
 * events.
 *
 * @since 1.3
 */
public interface SubscriberRegistry {

    /**
     * Registers all event handler methods on the specified instance to receive relevant events.  The handler methods
     * are determined by {@link SubscriberRegistry} implementations, typically by using an
     * {@link EventListenerResolver} (e.g. {@link AnnotationEventListenerResolver}).
     *
     * @param subscriber the object whose event handler methods should be registered to receive events.
     */
    void register(Object subscriber);

    /**
     * Unregisters all previously-registered event handler methods on the specified instance.  If the specified object
     * was not previously registered, calling this method has no effect.
     *
     * @param subscriber the previously
     */
    void unregister(Object subscriber);
}
