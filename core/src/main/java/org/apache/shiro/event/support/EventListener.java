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

/**
 * An event listener knows how to accept and process events of a particular type (or types).
 * <p/>
 * Note that this interface is in the event implementation support package (and not the event package directly)
 * because it is a supporting concept for event bus implementations and not something that most application
 * developers using Shiro should implement directly.  App developers should instead use the
 * {@link org.apache.shiro.event.Subscribe Subscribe} annotation on methods they wish to receive events.
 * <p/>
 * This interface therefore mainly represents a 'middle man' between the event bus and the actual subscribing
 * component.  As such, event bus implementors (or framework/infrastructural implementors) or those that wish to
 * customize listener/dispatch functionality might find this concept useful.
 * <p/>
 * It is a concept almost always used in conjunction with a {@link EventListenerResolver} implementation.
 *
 * @see SingleArgumentMethodEventListener
 * @see AnnotationEventListenerResolver
 *
 * @since 1.3
 */
public interface EventListener {

    /**
     * Returns {@code true} if the listener instance can process the specified event object, {@code false} otherwise.
     * @param event the event object to test
     * @return {@code true} if the listener instance can process the specified event object, {@code false} otherwise.
     */
    boolean accepts(Object event);

    /**
     * Handles the specified event.  Again, as this interface is an implementation concept, implementations of this
     * method will likely dispatch the event to a 'real' processor (e.g. method).
     *
     * @param event the event to handle.
     */
    void onEvent(Object event);
}
