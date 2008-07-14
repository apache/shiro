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
package org.jsecurity.logging;

import org.jsecurity.util.ClassUtils;
import org.jsecurity.util.JavaEnvironment;

/**
 * <p>JSecurity doesn't implement a Logging mechanism itself, since that is outside the core competency of a
 * Security framework.
 * <p>This class exists <b>ONLY</b> to support low coupling to 3rd party APIs and
 * graceful degredation.  This class initializes the underlying logging infrastructure and functions as follows:
 *
 * <ol>
 * <li>Is SLF4J in the classpath?  If so, use it for all logging operations.</li>
 * <li>If SLF4J is not in the classpath, are we on JRE 1.4?  If so, use a JDK Logger for all logging operations.</li>
 * <li>If SLF4J is not in the classpath and we are not at least JRE 1.4, disable logging entirely.</li>
 * </ol>
 *
 * <p>It is expected that all custom logging implementations (Log4J, Logback, etc) be enabled via SLF4J.  This is the
 * only logging abstraction framework JSecurity supports.</p>
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public final class JSecurityLogFactory {

    transient static LogFactory instance;

    static {
        try {
            instance = (LogFactory) ClassUtils.newInstance("org.jsecurity.logging.slf4j.Slf4jLogFactory");
            //ensure that the LogFactory can initialize:
            instance.getLog(JSecurityLogFactory.class.getName());
        } catch (Throwable t) {
            //SLF4J not available or not initialized properly, try remaining possibilities:
            if (JavaEnvironment.isAtLeastVersion14()) {
                instance = (LogFactory) ClassUtils.newInstance("org.jsecurity.logging.jdk.JdkLogFactory");
            } else {
                //SLF4J not available and on JRE 1.3.  Disable logging entirely for performance.
                //End-users must use SLF4J if they want logging on 1.3 environments:
                instance = new NoOpLogFactory();
            }
        }
    }

    public static Log getLog(String name) {
        return instance.getLog(name);
    }

    public static void setLogFactory(LogFactory instance) {
        if (instance == null) {
            throw new IllegalArgumentException("LogFactory instance cannot be null.");
        }
        JSecurityLogFactory.instance = instance;
    }

    public static LogFactory getLogFactory() {
        return instance;
    }
}
