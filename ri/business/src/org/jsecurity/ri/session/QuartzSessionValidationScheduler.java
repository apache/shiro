/*
 * Copyright (c) 2005 All rights reserved.
 */

package org.jsecurity.ri.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.SimpleTrigger;
import org.quartz.impl.StdSchedulerFactory;

/**
 * Description of class.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class QuartzSessionValidationScheduler implements SessionValidationScheduler {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final long DEFAULT_SESSION_VALIDATION_INTERVAL = 300000;

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());
    private SessionManager sessionManager;
    private long sessionValidationInterval = DEFAULT_SESSION_VALIDATION_INTERVAL;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public QuartzSessionValidationScheduler() {
    }


    public QuartzSessionValidationScheduler(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public void setSessionManager(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }


    public void setSessionValidationInterval(long sessionValidationInterval) {
        this.sessionValidationInterval = sessionValidationInterval;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public void startSessionValidation() {

        try {
            SimpleTrigger trigger = new SimpleTrigger( getClass().getName(),
                                                       Scheduler.DEFAULT_GROUP,
                                                       SimpleTrigger.REPEAT_INDEFINITELY,
                                                       sessionValidationInterval );

            Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
            //todo Finish scheduler setup
//            scheduler.scheduleJob( trigger );
        } catch (SchedulerException e) {
            if (logger.isErrorEnabled()) {
                logger.error("Error starting the Quartz session validation job.  Session validation may not occur.", e);
            }
        }

    }
}