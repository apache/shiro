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
package org.apache.shiro.event.support;

import java.util.List;

/**
 * An {@code EventListenerResolver} knows how to resolve (either create or lookup) {@link EventListener} instances
 * as a result of inspecting a subscriber object, mostly likely a
 * {@link org.apache.shiro.event.Subscribe Subscribe}-annotated object instance.
 * <p/>
 * This interface exists primarily as a support concept for the {@link DefaultEventBus} implementation.  Custom
 * implementations of this interface can be configured on a {@link DefaultEventBus} instance to determine exactly
 * how a subscriber receives events.
 * <p/>
 * For example, the {@link AnnotationEventListenerResolver AnnotationEventListenerResolver} will inspect a runtime
 * object for {@link org.apache.shiro.event.Subscribe Subscribe}-annotated methods, and for each method found, return
 * an {@link EventListener} instance representing the method to invoke.
 *
 * @see AnnotationEventListenerResolver
 * @see SingleArgumentMethodEventListener
 * @since 1.3
 */
public interface EventListenerResolver {

    /**
     * Returns {@link EventListener} instances as a result of inspecting a subscriber object, mostly likely with
     * {@link org.apache.shiro.event.Subscribe Subscribe}-annotated methods.
     *
     * @param instance the subscriber instance for which EventListener instances should be acquired.
     * @return {@link EventListener} instances as a result of inspecting a subscriber object.
     */
    List<EventListener> getEventListeners(Object instance);
}
