/*
 * Copyright 2005-2008 Jeremy Haile
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
