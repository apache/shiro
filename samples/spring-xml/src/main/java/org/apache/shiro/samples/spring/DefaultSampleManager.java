/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.samples.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;


/**
 * Default implementation of the {@link SampleManager} interface that stores
 * and retrieves a value from the user's session.
 *
 * @since 0.1
 */
public class DefaultSampleManager implements SampleManager {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * Key used to store the value in the user's session.
     */
    private static final String VALUE_KEY = "sample_value";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private static final Logger log = LoggerFactory.getLogger(DefaultSampleManager.class);

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
        String value = null;

        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession(false);
        if (session != null) {
            value = (String) session.getAttribute(VALUE_KEY);
            if (log.isDebugEnabled()) {
                log.debug("retrieving session key [" + VALUE_KEY + "] with value [" + value + "] on session with id [" + session.getId() + "]");
            }
        }

        return value;
    }

    public void setValue(String newValue) {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();

        if (log.isDebugEnabled()) {
            log.debug("saving session key [" + VALUE_KEY + "] with value [" + newValue + "] on session with id [" + session.getId() + "]");
        }

        session.setAttribute(VALUE_KEY, newValue);
    }

    public void secureMethod1() {
        if (log.isInfoEnabled()) {
            log.info("Secure method 1 called...");
        }
    }

    public void secureMethod2() {
        if (log.isInfoEnabled()) {
            log.info("Secure method 2 called...");
        }
    }

    public void secureMethod3() {
        if (log.isInfoEnabled()) {
            log.info("Secure method 3 called...");
        }
    }
}
