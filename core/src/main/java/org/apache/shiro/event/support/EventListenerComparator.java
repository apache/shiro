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

import java.util.Comparator;

/**
 * Compares two event listeners to determine the order in which they should be invoked when an event is dispatched.
 * The lower the order, the sooner it will be invoked (the higher its precedence).  The higher the order, the later
 * it will be invoked (the lower its precedence).
 * <p/>
 * TypedEventListeners have a higher precedence (i.e. a lower order) than standard EventListener instances.  Standard
 * EventListener instances have the same order priority.
 * <p/>
 * When both objects being compared are TypedEventListeners, they are ordered according to the rules of the
 * {@link EventClassComparator}, using the TypedEventListeners'
 * {@link TypedEventListener#getEventType() eventType}.
 *
 * @since 1.3
 */
public class EventListenerComparator implements Comparator<EventListener> {

    //event class comparator is stateless, so we can retain an instance:
    private static final EventClassComparator EVENT_CLASS_COMPARATOR = new EventClassComparator();

    public int compare(EventListener a, EventListener b) {
        if (a == null) {
            if (b == null) {
                return 0;
            } else {
                return -1;
            }
        } else if (b == null) {
            return 1;
        } else if (a == b || a.equals(b)) {
            return 0;
        } else {
            if (a instanceof TypedEventListener) {
                TypedEventListener ta = (TypedEventListener)a;
                if (b instanceof TypedEventListener) {
                    TypedEventListener tb = (TypedEventListener)b;
                    return EVENT_CLASS_COMPARATOR.compare(ta.getEventType(), tb.getEventType());
                } else {
                    return -1; //TypedEventListeners are 'less than' (higher priority) than non typed
                }
            } else {
                if (b instanceof TypedEventListener) {
                    return 1;
                } else {
                    return 0;
                }
            }
        }
    }
}
