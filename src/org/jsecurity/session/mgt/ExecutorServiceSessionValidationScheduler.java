package org.jsecurity.session.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * SessionValidationScheduler implementation that uses a
 * {@link ScheduledExecutorService} to call {@link ValidatingSessionManager#validateSessions()} every
 * <em>{@link #getInterval interval}</em> milliseconds.
 *
 * @author Les Hazlewood
 * @since Mar 14, 2008 8:00:20 PM
 */
public class ExecutorServiceSessionValidationScheduler implements SessionValidationScheduler, Runnable {

    protected transient final Log log = LogFactory.getLog(getClass());

    ValidatingSessionManager sessionManager;
    private ScheduledExecutorService service;
    private long interval = DefaultSessionManager.DEFAULT_SESSION_VALIDATION_INTERVAL;

    public ExecutorServiceSessionValidationScheduler() {
        super();
    }

    public ExecutorServiceSessionValidationScheduler( ValidatingSessionManager sessionManager ) {
        this.sessionManager = sessionManager;
    }

    public ValidatingSessionManager getSessionManager() {
        return sessionManager;
    }

    public void setSessionManager(ValidatingSessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    public long getInterval() {
        return interval;
    }

    public void setInterval(long interval) {
        this.interval = interval;
    }

    public void startSessionValidation() {
        if ( this.interval > 0l ) {
            this.service = Executors.newSingleThreadScheduledExecutor();
            this.service.scheduleAtFixedRate(this, interval, interval, TimeUnit.MILLISECONDS );
        }
    }

    public void run() {
        if( log.isDebugEnabled() ) {
            log.debug( "Executing session validation..." );
        }
        long startTime = System.currentTimeMillis();
        this.sessionManager.validateSessions();
        long stopTime = System.currentTimeMillis();
        if ( log.isDebugEnabled() ) {
            log.debug( "Session validation completed successfully in " + (stopTime - startTime) + " milliseconds.");
        }
    }

    public void stopSessionValidation() {
        this.service.shutdownNow();
    }
}
