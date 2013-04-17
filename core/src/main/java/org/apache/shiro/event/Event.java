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

import java.util.EventObject;

/**
 * Root class for all of Shiro's event classes.  Provides access to the timestamp when the event occurred.
 *
 * @since 1.3
 */
public abstract class Event extends EventObject {

    private final long timestamp; //millis since Epoch (UTC time zone).

    public Event(Object source) {
        super(source);
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * Returns the timestamp when this event occurred as the number of milliseconds since Epoch (UTC time zone).
     *
     * @return the timestamp when this event occurred as the number of milliseconds since Epoch (UTC time zone).
     */
    public long getTimestamp() {
        return this.timestamp;
    }
}
