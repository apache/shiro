/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
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
