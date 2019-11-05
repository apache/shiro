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

import static org.junit.Assert.*

/**
 * @since 1.3
 */
class AnnotationEventListenerResolverTest {

    @Test
    void testSetGetAnnotationClass() {
        def resolver = new AnnotationEventListenerResolver();
        resolver.setAnnotationClass(Override.class) //any old annotation will do for the test
        assertSame Override.class, resolver.getAnnotationClass()
    }

    @Test
    void testNullInstanceArgument() {
        def resolver = new AnnotationEventListenerResolver()
        def collection = resolver.getEventListeners(null)
        assertNotNull collection
        assertTrue collection.isEmpty()
    }

    @Test
    void testNoAnnotationsArgument() {
        def resolver = new AnnotationEventListenerResolver()
        def collection = resolver.getEventListeners(new NotAnnotatedSubscriber())
        assertNotNull collection
        assertTrue collection.isEmpty()
    }
}
