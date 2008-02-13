/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.session.event;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Simple implementation that only logs the events received.
 *
 * <p>This class should serve as a simple example to people writing listener implementations to handle events in a
 * custom application.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class LoggingSessionEventListener implements SessionEventListener {

    protected transient final Log log = LogFactory.getLog( getClass() );

    public LoggingSessionEventListener(){}

    public void onEvent( SessionEvent event ) {
        //only incur stack execution overhead if the logging messages will actually be output:
        if ( log.isDebugEnabled() ) {
            accept( event );
        }
    }

    protected void accept( StartedSessionEvent event ) {
        String msg = "Session started; id = [" + event.getSessionId() + "]";
        log.debug( msg );
    }

    protected void accept( StoppedSessionEvent event ) {
        String msg = "Session stopped; id = [" + event.getSessionId() + "]";
        log.debug( msg );
    }

    protected void accept( ExpiredSessionEvent event ) {
        String msg = "Session expired; id = [" + event.getSessionId() + "]";
        log.debug( msg );
    }

    protected void accept( SessionEvent event ) {
        String msg = "Received unrecognized event of type [" + event.getClass().getName() + "] for session with " +
            "id [" + event.getSessionId() + "].";
        log.debug( msg );
    }
}
