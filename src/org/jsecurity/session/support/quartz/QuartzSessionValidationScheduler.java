/*
 * Copyright (C) 2005-2007 Les Hazlewood, Jeremy Haile
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
package org.jsecurity.session.support.quartz;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.session.support.SessionValidationScheduler;
import org.jsecurity.session.support.ValidatingSessionManager;
import org.quartz.JobDetail;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.SimpleTrigger;
import org.quartz.impl.StdSchedulerFactory;

/**
 * An implementation of the {@link SessionValidationScheduler SessionValidationScheduler} that uses Quartz to schedule a
 * job to call {@link org.jsecurity.session.support.ValidatingSessionManager#validateSessions()} on
 * a regular basis.
 *
 * @author Jeremy Haile
 * @since 0.1
 */
public class QuartzSessionValidationScheduler implements SessionValidationScheduler {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * The default interval at which sessions will be validated.(5 minutes)
     * This can be overridden by calling {@link #setSessionValidationInterval(long)}
     */
    private static final long DEFAULT_SESSION_VALIDATION_INTERVAL = 300000;

    /**
     * The name assigned to the quartz job.
     */
    private static final String JOB_NAME = "SessionValidationJob";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logging logger
     */
    protected final transient Log log = LogFactory.getLog( getClass() );

    /**
     * The configured Quartz scheduler to use to schedule the Quartz job.  If no scheduler is
     * configured, the schedular will be retrieved by calling {@link StdSchedulerFactory#getDefaultScheduler()}
     */
    private Scheduler scheduler;

    private boolean schedulerImplicitlyCreated = false;

    /**
     * The session manager used to validate sessions.
     */
    private ValidatingSessionManager sessionManager;

    /**
     * The session validation interval in milliseconds.
     */
    private long sessionValidationInterval = DEFAULT_SESSION_VALIDATION_INTERVAL;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /**
     * Default constructor.
     */
    public QuartzSessionValidationScheduler() {
    }

    /**
     * Constructor that specifies the session manager that should be used for validating sessions.
     *
     * @param sessionManager the <tt>SessionManager</tt> that should be used to validate sessions.
     */
    public QuartzSessionValidationScheduler( ValidatingSessionManager sessionManager ) {
        this.sessionManager = sessionManager;
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    protected Scheduler getScheduler() throws SchedulerException {
        if ( scheduler == null ) {
            scheduler = StdSchedulerFactory.getDefaultScheduler();
            schedulerImplicitlyCreated = true;
        }
        return scheduler;
    }

    public void setScheduler( Scheduler scheduler ) {
        this.scheduler = scheduler;
    }

    public void setSessionManager( ValidatingSessionManager sessionManager ) {
        this.sessionManager = sessionManager;
    }


    public void setSessionValidationInterval( long sessionValidationInterval ) {
        this.sessionValidationInterval = sessionValidationInterval;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * Starts session validation by creating a Quartz simple trigger, linking it to
     * the {@link QuartzSessionValidationJob}, and scheduling it with the Quartz scheduler.
     */
    public void startSessionValidation() {

        if ( log.isDebugEnabled() ) {
            log.debug( "Scheduling session validation job using Quartz with " +
                "session validation interval of [" + sessionValidationInterval + "]ms..." );
        }

        try {
            SimpleTrigger trigger = new SimpleTrigger( getClass().getName(),
                Scheduler.DEFAULT_GROUP,
                SimpleTrigger.REPEAT_INDEFINITELY,
                sessionValidationInterval );

            JobDetail detail = new JobDetail( JOB_NAME, Scheduler.DEFAULT_GROUP, QuartzSessionValidationJob.class );
            detail.getJobDataMap().put( QuartzSessionValidationJob.SESSION_MANAGER_KEY, sessionManager );

            Scheduler scheduler = getScheduler();

            scheduler.scheduleJob( detail, trigger );
            if ( schedulerImplicitlyCreated ) {
                scheduler.start();
                if ( log.isDebugEnabled() ) {
                    log.debug( "Successfully started implicitly created Quartz Scheduler instance." );
                }
            }

            if ( log.isDebugEnabled() ) {
                log.debug( "Session validation job successfully scheduled with Quartz." );
            }

        } catch ( SchedulerException e ) {
            if ( log.isErrorEnabled() ) {
                log.error( "Error starting the Quartz session validation job.  Session validation may not occur.", e );
            }
        }
    }

    public void stopSessionValidation() {
        if ( log.isDebugEnabled() ) {
            log.debug( "Stopping Quartz session validation job..." );
        }

        Scheduler scheduler;
        try {
            scheduler = getScheduler();
            if ( scheduler == null ) {
                if ( log.isWarnEnabled() ) {
                    log.warn( "getScheduler() method returned a null Quartz scheduler, which is unexpected.  Please " +
                        "check your configuration and/or implementation.  Returning quietly since there is no " +
                        "validation job to remove (scheduler does not exist)." );
                }
                return;
            }
        } catch ( SchedulerException e ) {
            if ( log.isWarnEnabled() ) {
                log.warn( "Unable to acquire Quartz Scheduler.  Ignoring and returning (already stopped?)", e );
            }
            return;
        }

        try {
            scheduler.unscheduleJob( JOB_NAME, Scheduler.DEFAULT_GROUP );
            if ( log.isDebugEnabled() ) {
                log.debug( "Quartz session validation job stopped successfully." );
            }
        } catch ( SchedulerException e ) {
            if ( log.isInfoEnabled() ) {
                log.info( "Could not cleanly remove SessionValidationJob from Quartz scheduler.  " +
                    "Ignoring and stopping.", e );
            }
        }

        if ( schedulerImplicitlyCreated ) {
            try {
                scheduler.shutdown();
            } catch ( SchedulerException e ) {
                if ( log.isWarnEnabled() ) {
                    log.warn( "Unable to cleanly shutdown implicitly created Quartz Scheduler instance.", e );
                }
            } finally {
                setScheduler( null );
                schedulerImplicitlyCreated = false;
            }
        }


    }
}