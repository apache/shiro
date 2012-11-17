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


import org.apache.shiro.event.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A default event bus implementation that synchronously publishes events to registered listeners.  Listeners can be
 * registered or unregistered for events as necessary.
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
 * concept, although no code was shared/imported (even though Guava is Apache 2.0 licensed and could have
 * been used).
 *
 * @since 1.3
 */
public class DefaultEventBus implements Publisher, SubscriberRegistry {

    private static final Logger log = LoggerFactory.getLogger(DefaultEventBus.class);

    private EventListenerResolver eventListenerResolver;

    private final Map<Object,Subscriber> registry;

    public DefaultEventBus() {
        this.registry = new ConcurrentHashMap<Object, Subscriber>();
        this.eventListenerResolver = new AnnotationEventListenerResolver();
    }

    public EventListenerResolver getEventListenerResolver() {
        return eventListenerResolver;
    }

    public void setEventListenerResolver(EventListenerResolver eventListenerResolver) {
        this.eventListenerResolver = eventListenerResolver;
    }

    public void publish(Object event) {
        if (event == null) {
            log.info("Received null event for publishing.  Ignoring and returning.");
            return;
        }

        for( Subscriber subscriber : registry.values() ) {
            subscriber.onEvent(event);
        }
    }

    public void register(Object instance) {
        if (instance == null) {
            log.info("Received null instance for registration.  Ignoring registration request.");
            return;
        }

        unregister(instance);

        List<EventListener> listeners = getEventListenerResolver().getEventListeners(instance);

        if (listeners == null || listeners.isEmpty()) {
            log.warn("Unable to resolve any event listeners for the subscriber instance [" + instance +
                    "].  Ignoring registration request.");
            return;
        }

        Subscriber subscriber = new Subscriber(instance, listeners);

        this.registry.put(instance, subscriber);
    }

    public void unregister(Object instance) {
        if (instance == null) {
            return;
        }
        this.registry.remove(instance);
    }

    private class Subscriber {

        private final Object instance;
        private final List<EventListener> registeredListeners;

        public Subscriber(Object instance, List<EventListener> listeners) {
            this.instance = instance;
            List<EventListener> toSort = new ArrayList<EventListener>(listeners);
            Collections.sort(toSort, new EventListenerComparator());
            this.registeredListeners = toSort;
        }

        public void onEvent(Object event) {

            Set<Object> delivered = new HashSet<Object>();

            for(EventListener listener : this.registeredListeners) {
                Object target = listener;
                if (listener instanceof SingleArgumentMethodEventListener) {
                    SingleArgumentMethodEventListener singleArgListener = (SingleArgumentMethodEventListener)listener;
                    target = singleArgListener.getTarget();
                }
                if (listener.accepts(event) && !delivered.contains(target)) {
                    try {
                        listener.onEvent(event);
                        delivered.add(target);
                    } catch (Throwable t) {
                        log.warn("Event listener processing failed.  Listeners should generally " +
                                "handle exceptions directly and not propagate to the event bus.", t);
                    }
                }
            }
        }
    }
}
