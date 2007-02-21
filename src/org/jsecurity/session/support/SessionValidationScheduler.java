/*
 * Copyright (C) 2005-2007 All rights reserved.
 */

package org.jsecurity.session.support;

/**
 * Interface that should be implemented by classes that can control validating sessions on a regular
 * basis.  This interface is used as a delegate for session validation by the {@link DefaultSessionManager}
 *
 * @see org.jsecurity.session.support.DefaultSessionManager#setSessionValidationScheduler(SessionValidationScheduler)
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public interface SessionValidationScheduler {

    /**
     * Starts the session validation job.
     */
    void startSessionValidation();

    /**
     * Stops the session validation job.
     */    
    void stopSessionValidation();

}