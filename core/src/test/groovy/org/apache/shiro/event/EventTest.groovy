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
package org.apache.shiro.event

import org.junit.Test

import static org.junit.Assert.assertSame
import static org.junit.Assert.assertTrue

/**
 * @since 1.3
 */
class EventTest {

    @Test
    void testDefault() {
        Object source = new Object()
        long start = System.currentTimeMillis()
        Event e = new DummyEvent(source)
        long stop = System.currentTimeMillis()

        assertSame source, e.source
        assertTrue start <= e.timestamp
        assertTrue stop >= e.timestamp
    }

    private class DummyEvent extends Event {
        DummyEvent(Object source) {
            super(source)
        }
    }
}
