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
package org.jsecurity.subject;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;

/**
 * A RememberMeManager is responsible for remembering a Subject's identity across that subject's sessions with
 * the application.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public interface RememberMeManager {

    PrincipalCollection getRememberedPrincipals();

    void onSuccessfulLogin(AuthenticationToken token, Account account);

    void onFailedLogin(AuthenticationToken token, AuthenticationException ae);

    void onLogout(PrincipalCollection subjectPrincipals);
}
