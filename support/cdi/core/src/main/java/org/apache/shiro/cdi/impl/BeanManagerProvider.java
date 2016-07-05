/**
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
package org.apache.shiro.cdi.impl;

import javax.enterprise.inject.spi.BeanManager;
import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * Provides access to the current bean manager. If the bean manager cannot be found under the
 * canonical JNDI name (e.g. when the application is not running in a Java EE environment), this
 * class returns a singleton which must be set explicitly by the user with
 * {@link #setBeanManager(BeanManager)}.
 * <p>
 * TODO In CDI 1.1, CDI.current().getBeanManager() should be used instead.
 */
public class BeanManagerProvider {

    private static BeanManager beanManager;
    

    /** Hidden constructor. */
    private BeanManagerProvider() {
    }

    /**
     * Looks up the current bean manager in JNDI, or returns the value set by
     * {@link #setBeanManager(BeanManager)} as fallback.
     * 
     * @return
     */
    public static BeanManager getBeanManager() {
        try {
            InitialContext initialContext = new InitialContext();
            return (BeanManager) initialContext.lookup("java:comp/BeanManager");
        }
        catch (NamingException e) {
            if (beanManager != null) {
                return beanManager;
            }
            throw new IllegalStateException(
                "BeanManager not found in JNDI and not set via setBeanManager()");
        }
    }

    /**
     * @param beanManager
     *            the beanManager to set
     */
    public static void setBeanManager(BeanManager beanManager) {
        BeanManagerProvider.beanManager = beanManager;
    }

}
