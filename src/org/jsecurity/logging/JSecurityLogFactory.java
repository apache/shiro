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

import org.jsecurity.logging.console.ConsoleLogFactory;
import org.jsecurity.logging.jdk.JdkLogFactory;
import org.jsecurity.util.JavaEnvironment;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public final class JSecurityLogFactory {

    transient static LogFactory instance;

    static {
        if (JavaEnvironment.isAtLeastVersion14()) {
            instance = new JdkLogFactory();
        } else {
            instance = new ConsoleLogFactory();
        }
    }

    public static void setLogFactory(LogFactory instance) {
        JSecurityLogFactory.instance = instance;
    }

    public static LogFactory getLogFactory() {
        return instance;
    }

    public static Log getLog(String name) {
        return instance.getLog(name);
    }

}
