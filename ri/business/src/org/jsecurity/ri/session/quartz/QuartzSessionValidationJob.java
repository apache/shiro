package org.jsecurity.ri.session.quartz;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.ri.session.ValidatingSessionManager;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.scheduling.quartz.QuartzJobBean;

/**
 * A quartz job that basically just calls the {@link org.jsecurity.ri.session.ValidatingSessionManager#validateSessions()}
 * method on a configured session manager.  The session manager will automatically be injected by the
 * superclass if it is in the job data map or the scheduler map.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class QuartzSessionValidationJob extends QuartzJobBean {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logger.
     */
    protected transient final Log log = LogFactory.getLog( getClass() );

    /**
     * Session manager used to validate sessions.
     */
    private ValidatingSessionManager sessionManager;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public void setSessionManager(ValidatingSessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * Called when the job is executed by quartz.  This method delegates to the
     * <tt>validateSessions()</tt> method on the associated session manager.
     * @param context the Quartz job execution context for this execution.
     */
    protected void executeInternal(JobExecutionContext context) throws JobExecutionException {
        if( log.isDebugEnabled() ) {
            log.debug( "Executing session validation Quartz job..." );
        }

        sessionManager.validateSessions();

        if( log.isDebugEnabled() ) {
            log.debug( "Session validation Quartz job complete." );
        }
    }
}
