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
 * An event bus can publish events to event subscribers as well as provide a mechanism for registering and unregistering
 * event subscribers.
 * <p/>
 * An event bus enables a publish/subscribe paradigm within Shiro - components can publish or consume events they
 * find relevant without needing to be tightly coupled to other components.  This affords great
 * flexibility within Shiro by promoting loose coupling and high cohesion between components and a much safer pluggable
 * architecture.
 * <h2>Sending Events</h2>
 * If a component wishes to publish events to other components:
 * <pre>
 *     MyEvent myEvent = createMyEvent();
 *     eventBus.publish(myEvent);
 * </pre>
 * The event bus will determine the type of event and then dispatch the event to components that wish to receive
 * events of that type.
 * <h2>Receiving Events</h2>
 * A component can receive events of interest by doing the following.
 * <ol>
 *     <li>For each type of event you wish to consume, create a public method that accepts a single event argument.
 *     The method argument type indicates the type of event to receive.</li>
 *     <li>Annotate each of these public methods with the {@link org.apache.shiro.event.Subscribe Subscribe} annotation.</li>
 *     <li>Register the component with the event bus:
 *     <pre>
 *         eventBus.register(myComponent);
 *     </pre>
 *     </li>
 * </ol>
 * After registering the component, when when an event of a respective type is published, the component's
 * {@code Subscribe}-annotated method(s) will be invoked as expected.
 * <p/>
 * This design (and its constituent helper components) was largely influenced by
 * Guava's <a href="http://docs.guava-libraries.googlecode.com/git/javadoc/com/google/common/eventbus/EventBus.html">EventBus</a>
 * concept, although no code was viewed/copied/imported (even though Guava code is Apache 2.0 licensed and could have
 * been used).
 *
 * @since 1.3
 */
public interface EventBus {

    /**
     * Publishes the specified event to an event subsystem that will deliver events to relevant {@link Subscribe}rs.
     *
     * @param event The event object to distribute to relevant subscribers.
     */
    void publish(Object event);

    /**
     * Registers all event handler methods on the specified instance to receive relevant events.  The handler methods
     * are determined by the {@code EventBus} implementation, typically by using an
     * {@link org.apache.shiro.event.support.EventListenerResolver EventListenerResolver}
     * (e.g. {@link org.apache.shiro.event.support.AnnotationEventListenerResolver AnnotationEventListenerResolver}).
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
