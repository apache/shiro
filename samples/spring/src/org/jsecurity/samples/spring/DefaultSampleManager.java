/*
 * Copyright (C) 2007 Jeremy Haile
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
package org.jsecurity.samples.spring;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.SecurityUtils;
import org.jsecurity.session.Session;
import org.jsecurity.subject.Subject;

/**
 * Default implementation of the {@link SampleManager} interface that stores
 * and retrieves a value from the user's session.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class DefaultSampleManager implements SampleManager {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * Key used to store the value in the user's session.
     */
    private static final String VALUE_KEY = "value";

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
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession( false );
        if( session != null ) {
            return (String) session.getAttribute(VALUE_KEY);
        } else {
            return null;
        }
    }

    public void setValue( String newValue ) {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        session.setAttribute(VALUE_KEY, newValue );
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
