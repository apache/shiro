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
package org.apache.shiro.session.mgt;

import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;


/**
 * A <code>ValidatingSession</code> is a <code>Session</code> that is capable of determining it is valid or not and
 * is able to validate itself if necessary.
 * <p/>
 * Validation is usually an exercise of determining when the session was last accessed or modified and determining if
 * that time is longer than a specified allowed duration.
 * 
 * @since 0.9
 */
public interface ValidatingSession extends Session {

    boolean isValid();

    void validate() throws InvalidSessionException;
}
