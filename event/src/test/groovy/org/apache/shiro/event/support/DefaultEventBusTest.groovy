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
package org.apache.shiro.event.support

import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*
import static org.easymock.EasyMock.*

/**
 * @since 1.3
 */
class DefaultEventBusTest {

    DefaultEventBus bus;

    @Before
    void setUp() {
        bus = new DefaultEventBus()
    }

    @Test
    void testSetEventListenerResolver() {
        def resolver = new EventListenerResolver() {
            List<EventListener> getEventListeners(Object instance) {
                return null //dummy implementation
            }
        }
        bus.setEventListenerResolver(resolver)
        assertSame resolver, bus.getEventListenerResolver()
    }

    @Test
    void testSimpleSubscribe() {
        def subscriber = new TestSubscriber();

        bus.register(subscriber);

        def event = new FooEvent(this)

        bus.publish(event)

        assertEquals 1, subscriber.fooCount
        assertEquals 1, subscriber.count
        assertSame event, subscriber.lastEvent
    }

    @Test
    void testPublishNullEvent() {
        def subscriber = new TestSubscriber();
        bus.register(subscriber)

        bus.publish(null)

        assertEquals 0, subscriber.count
    }

    @Test
    void testSubscribeNullInstance() {
        def resolver = createStrictMock(EventListenerResolver)  //assert no methods are called on this
        bus.eventListenerResolver = resolver

        replay(resolver)

        bus.register(null)

        verify(resolver)
    }

    @Test
    void testSubscribeWithNullResolvedListeners() {
        def resolver = new EventListenerResolver() {
            List<EventListener> getEventListeners(Object instance) {
                return null //dummy implementation
            }
        }
        bus.setEventListenerResolver(resolver)
        def subscriber = new NotAnnotatedSubscriber()
        bus.register(subscriber);
        assertEquals 0, bus.registry.size()
    }

    @Test
    void testSubscribeWithoutAnnotations() {
        def subscriber = new NotAnnotatedSubscriber()
        bus.register(subscriber)

        bus.publish(new FooEvent(this))

        assertEquals 0, bus.registry.size()
    }

    @Test
    void testUnsubscribeNullInstance() {
        bus.unregister(null)
    }

    @Test
    void testUnsubscribe() {
        def subscriber = new TestSubscriber()
        bus.register(subscriber)
        assertEquals 1, bus.registry.size()

        def event = new FooEvent(this)

        bus.publish(event)

        assertSame event, subscriber.lastEvent
        assertEquals 1, subscriber.fooCount
        assertEquals 1, subscriber.count

        bus.unregister(subscriber)

        assertEquals 0, bus.registry.size()
    }

    @Test
    void testPolymorphicSubscribeMethodsOnlyOneInvoked() {
        def subscriber = new TestSubscriber()
        bus.register(subscriber)

        def event = new BarEvent(this)

        bus.publish(event)

        assertSame event, subscriber.lastEvent
        assertEquals 0, subscriber.fooCount
        assertEquals 1, subscriber.barCount
        assertEquals 1, subscriber.count
    }

    @Test
    void testPolymorphicSubscribeMethodsOnlyOneInvokedWithListenerSubclass() {
        def subscriber = new SubclassTestSubscriber()
        bus.register(subscriber)

        def event = new BazEvent(this)

        bus.publish(event)

        assertSame event, subscriber.lastEvent
        assertEquals 1, subscriber.count
        assertEquals 1, subscriber.bazCount
        assertEquals 0, subscriber.fooCount
        assertEquals 0, subscriber.barCount
    }

    @Test
    void testSubscribeWithErroneousAnnotation() {
        def subscriber = new ErroneouslyAnnotatedSubscriber()
        //noinspection GroovyUnusedCatchParameter
        try {
            bus.register(subscriber)
            fail("exception expected")
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testContinueThroughListenerExceptions() {
        def ok = new SimpleSubscriber()
        def error = new ExceptionThrowingSubscriber()

        bus.register(ok)
        bus.register(error)

        bus.publish(new ErrorCausingEvent())
        bus.publish(new SimpleEvent())

        assertEquals 1, ok.count
        assertEquals 0, error.count
    }

}
