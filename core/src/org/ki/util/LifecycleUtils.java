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
package org.ki.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ki.JSecurityException;

import java.util.Collection;

/**
 * TODO - complete JavaDoc
 * @author Les Hazlewood
 * @since 0.2
 */
public abstract class LifecycleUtils {

    private static final Log log = LogFactory.getLog(LifecycleUtils.class);

    public static void init(Object o) throws JSecurityException {
        if (o instanceof Initializable) {
            init((Initializable) o);
        }
    }

    public static void init(Initializable initializable) throws JSecurityException {
        initializable.init();
    }

    /**
     * @param c
     * @throws JSecurityException
     * @since 0.9
     */
    public static void init(Collection c) throws JSecurityException {
        if (c == null || c.isEmpty()) {
            return;
        }
        for (Object o : c) {
            init(o);
        }
    }

    public static void destroy(Object o) {
        if (o instanceof Destroyable) {
            destroy((Destroyable) o);
        }
    }

    public static void destroy(Destroyable d) {
        if (d != null) {
            try {
                d.destroy();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    String msg = "Unable to cleanly destroy instance [" + d + "] of type [" + d.getClass().getName() + "].";
                    log.debug(msg, t);
                }
            }
        }
    }

    /**
     * Calls {@link #destroy(Object) destroy} for each object in the collection.  If the collection is <code>null</code> or
     * empty, this method returns quietly.
     *
     * @param c the collection of objects to destroy.
     * @since 0.9
     */
    public static void destroy(Collection c) {
        if (c == null || c.isEmpty()) {
            return;
        }

        for (Object o : c) {
            destroy(o);
        }
    }
}
