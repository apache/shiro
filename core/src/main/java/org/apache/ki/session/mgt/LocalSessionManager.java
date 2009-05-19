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
package org.apache.ki.session.mgt;

import org.apache.ki.session.Session;

/**
 * A {@code SessionManager} that is available in a local VM only.  It is not intended to be accessible
 * in remoting scenarios.
 *
 * @author Les Hazlewood
 * @since Mar 26, 2009 2:34:44 PM
 */
public interface LocalSessionManager extends SessionManager {

    /**
     * Returns the currently accessible {@link Session} based on the runtime environment.  This is mostly
     * returned from a ThreadLocal, static memory or based on thread-bound Request/Response pair in a Web
     * environment.
     *
     * @return the currently accessible {@link Session} based on the runtime environment.
     */
    Session getCurrentSession();


}
