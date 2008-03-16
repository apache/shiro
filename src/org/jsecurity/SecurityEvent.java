/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity;

import java.text.DateFormat;
import java.util.Date;
import java.util.EventObject;

/**
 * Root class of all events triggered by JSecurity.
 *
 * @since 0.9
 * @author Les Hazlewood
 */
public abstract class SecurityEvent extends EventObject {

    /**
     * The time at which this event took place.
     */
    protected Date timestamp = new Date();

    /**
     * Creates a new <tt>SecurityEvent</tt> for the given source.
     * @param source the source responsible or related to the event.
     */
    public SecurityEvent( Object source ) {
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
    
    public final String toString() {
        return toStringBuffer().toString();
    }

    protected StringBuffer toStringBuffer() {
        return new StringBuffer( DateFormat.getInstance().format(getTimestamp()) );
    }

}
