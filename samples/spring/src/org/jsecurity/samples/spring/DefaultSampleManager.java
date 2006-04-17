package org.jsecurity.samples.spring;

import org.jsecurity.session.Session;
import org.jsecurity.context.SecurityContext;

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
        Session session = SecurityContext.getSession();
        return (String) session.getAttribute( "value" );
    }

}
