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
package org.apache.shiro.cdi

import org.apache.deltaspike.testcontrol.api.junit.CdiTestRunner
import org.apache.shiro.event.EventBus
import org.junit.Test
import org.junit.runner.RunWith

import javax.inject.Inject

import static org.junit.Assert.*

@RunWith(CdiTestRunner.class)
public class EventBusSubscribeTest {

    @Inject
    EventBus eventBus

    @Inject
    EventListenerStub listenerStub

    @Inject
    EventBusAwareStub eventBusAwareStub

    @Test
    void fireEventTest() {

        // fire an event then make sure the wired component received it.
        eventBus.publish("EventString")
        assertEquals "EventString", listenerStub.lastEvent
    }

    @Test
    void eventBusAwareTest() {
        assertSame eventBus, eventBusAwareStub.eventBus
    }

}
