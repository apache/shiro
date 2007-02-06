package org.jsecurity.samples.spring;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.context.support.ThreadLocalSecurityContext;
import org.jsecurity.session.Session;

/**
 * Insert JavaDoc here.
 */
public class DefaultSampleManager implements SampleManager {

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

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public String getValue() {
        Session session = ThreadLocalSecurityContext.current().getSession( false );
        if( session != null ) {
            return (String) session.getAttribute( "value" );
        } else {
            return null;
        }
    }

    public void setValue(String newValue) {
        Session session = ThreadLocalSecurityContext.current().getSession( false );
        if( session != null ) {
            session.setAttribute( "value", newValue );
        }
    }

    public void secureMethod1() {
        if( log.isInfoEnabled() ) {
            log.info( "Secure method 1 called..." );
        }
    }

    public void secureMethod2() {
        if( log.isInfoEnabled() ) {
            log.info( "Secure method 2 called..." );
        }
    }

}
