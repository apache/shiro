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
package org.jsecurity;

import java.text.DateFormat;
import java.util.Date;
import java.util.EventObject;

/**
 * Root class of all events triggered by JSecurity.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class SecurityEvent extends EventObject {

    /**
     * The timestamp at which this event took place.
     */
    protected Date timestamp = new Date();

    /**
     * Creates a new <tt>SecurityEvent</tt> for the given source.
     *
     * @param source the source responsible or related to the event.
     */
    public SecurityEvent(Object source) {
        super(source);
    }


    /**
     * Returns the timestamp associated with this event.
     *
     * @return the timestamp associated with this event.
     */
    public Date getTimestamp() {
        return timestamp;
    }

    /**
     * A final method which just returns <code>toStringBuffer().toString();</code>, forcing subclasses to utilize the
     * more efficient StringBuffer class for String output.
     *
     * @return <code>toStringBuffer().toString()</code>, a more performant way of representing String output.
     */
    public final String toString() {
        return toStringBuffer().toString();
    }

    /**
     * Returns the <code>toString()</code> representation of the event, only utilizing a
     * {@link StringBuffer StringBuffer} for better performance.
     *
     * <p>The default implementation only returns a StringBuffer with the locale-specific
     * {@link #getTimestamp() timestamp} string:
     *
     * <pre><code>return new StringBuffer( DateFormat.getInstance().format( getTimestamp() ) );</code></pre>.
     *
     * @return the <code>toString()</code> representation of this object via a more efficient StringBuffer instance.
     */
    protected StringBuffer toStringBuffer() {
        return new StringBuffer(DateFormat.getInstance().format(getTimestamp()));
    }

}
