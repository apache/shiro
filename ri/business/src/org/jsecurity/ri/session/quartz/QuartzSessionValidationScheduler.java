/*
 * Copyright (c) 2005 All rights reserved.
 */

package org.jsecurity.ri.session.quartz;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.ri.session.SessionValidationScheduler;
import org.jsecurity.ri.session.ValidatingSessionManager;
import org.quartz.JobDetail;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.SimpleTrigger;
import org.quartz.impl.StdSchedulerFactory;

/**
 * An implementation of the {@link SessionValidationScheduler SessionValidationScheduler} that uses Quartz to schedule a
 * job to call {@link org.jsecurity.ri.session.ValidatingSessionManager#validateSessions()} on
 * a regular basis.
 *
 * @since 0.1
 * @author Jeremy Haile
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
    protected final transient Log log = LogFactory.getLog(getClass());

    /**
     * The configured Quartz scheduler to use to schedule the Quartz job.  If no scheduler is
     * configured, the schedular will be retrieved by calling {@link StdSchedulerFactory#getDefaultScheduler()}
     */
    private Scheduler scheduler;

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
     * @param sessionManager
     */
    public QuartzSessionValidationScheduler(ValidatingSessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    protected Scheduler getScheduler() throws SchedulerException {
        if( scheduler == null ) {
            return StdSchedulerFactory.getDefaultScheduler();
        } else {
            return scheduler;
        }
    }

    public void setScheduler(Scheduler scheduler) {
        this.scheduler = scheduler;
    }

    public void setSessionManager(ValidatingSessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }


    public void setSessionValidationInterval(long sessionValidationInterval) {
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

        if( log.isDebugEnabled() ) {
            log.debug( "Scheduling session validation job using Quartz with " +
                    "session validation interval of [" + sessionValidationInterval + "]ms..." );
        }

        try {
            SimpleTrigger trigger = new SimpleTrigger( getClass().getName(),
                                                       Scheduler.DEFAULT_GROUP,
                                                       SimpleTrigger.REPEAT_INDEFINITELY,
                                                       sessionValidationInterval );

            JobDetail detail = new JobDetail( JOB_NAME, Scheduler.DEFAULT_GROUP, QuartzSessionValidationJob.class );
            detail.getJobDataMap().put( "sessionManager", sessionManager );

            getScheduler().scheduleJob( detail, trigger );
            getScheduler().start();
            
            if( log.isDebugEnabled() ) {
                log.debug( "Session validation job successfully scheduled with Quartz." );
            }

        } catch (SchedulerException e) {
            if (log.isErrorEnabled()) {
                log.error("Error starting the Quartz session validation job.  Session validation may not occur.", e);
            }
        }

    }
}