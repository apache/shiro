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

import org.junit.Test

import java.lang.reflect.Method

import static org.junit.Assert.*

/**
 * @since 1.3
 */
class SingleArgumentMethodEventListenerTest {

    @Test
    void testInvalidConstruction() {

        def target = new Object()

        def method = Object.class.getMethod("hashCode") //any method without a single arg will do

        try {
            //noinspection GroovyResultOfObjectAllocationIgnored
            new SingleArgumentMethodEventListener(target, method)
            fail("exception expected")
        } catch (IllegalArgumentException iae) {
            assertEquals iae.message, "Event handler methods must accept a single argument."
        }
    }

    @Test
    void testValidConstruction() {

        def target = new TestSubscriber()
        def method = TestSubscriber.class.getMethods().find { it.name == "onFooEvent" }

        def listener = new SingleArgumentMethodEventListener(target, method)

        assertSame target, listener.getTarget()
        assertSame method, listener.getMethod()
    }

    @Test
    void testMethodException() {

        def target = new TestSubscriber()
        def method = TestSubscriber.class.getMethods().find { it.name == "onFooEvent" }

        def listener = new SingleArgumentMethodEventListener(target, method) {
            @Override
            Method getMethod() {
                //sneakily swap out the valid method with an erroneous one.  This wouldn't ever happen normally, we're
                //just doing this as a test harness:
                return Object.class.getMethods()[0] //any method will do
            }
        }

        //now invoke the erroneous method and ensure we get an exception:
        try {
            listener.onEvent(new FooEvent(this))
            fail("exception expected")
        } catch (IllegalStateException ise) {
            assertTrue ise.message.startsWith("Unable to invoke event handler method")
        }
    }

    @Test
    void testAccepts() {
        def target = new TestSubscriber()
        def method = TestSubscriber.class.getMethods().find { it.name == "onFooEvent" }

        def listener = new SingleArgumentMethodEventListener(target, method)

        assertTrue listener.accepts(new FooEvent(this))
    }

    @Test(expected=IllegalArgumentException)
    void testNonPublicMethodSubscriber() {
        def target = new InvalidMethodModiferSubscriber()
        def method = InvalidMethodModiferSubscriber.class.getDeclaredMethods().find { it.name == "onEvent" }

        new SingleArgumentMethodEventListener(target, method)
    }



}
