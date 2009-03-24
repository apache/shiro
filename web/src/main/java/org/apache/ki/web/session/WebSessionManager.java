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
package org.apache.ki.web.session;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.ki.session.Session;
import org.apache.ki.session.mgt.SessionManager;


/**
 * A <code>WebSessionManager</code> is a <code>SessionManager</code> that has the ability to obtain
 * {@link Session Session}s based on a {@link ServletRequest ServletRequest}/{@link ServletResponse ServletResponse}
 * pair.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public interface WebSessionManager extends SessionManager {

    /**
     * Returns the current {@link Session Session} associated with the specified request pair, or
     * <code>null</code> if there is no session associated with the request.
     * 
     * @param request the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return the current {@link Session Session} associated with the specified request pair, or
     * <code>null</code> if there is no session associated with the request. 
     */
    Session getSession(ServletRequest request, ServletResponse response);

}
