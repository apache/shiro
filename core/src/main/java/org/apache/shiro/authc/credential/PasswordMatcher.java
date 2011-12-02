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
package org.apache.shiro.authc.credential;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.util.ByteSource;

/**
 * A {@link CredentialsMatcher} that employs best-practices comparisons for hashed text passwords.
 * <p/>
 * This implementation delegates to an internal {@link PasswordService} to perform the actual password
 * comparison.  This class is essentially a bridge between the generic CredentialsMatcher interface and the
 * more specific {@code PasswordService} component.
 *
 * @since 1.2
 */
public class PasswordMatcher implements CredentialsMatcher {

    private PasswordService passwordService;

    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        PasswordService service = ensurePasswordService();
        ByteSource submittedPassword = getSubmittedPassword(token);
        String hashedPassword = getStoredHashedPassword(info);
        return service.passwordsMatch(submittedPassword, hashedPassword);
    }

    private PasswordService ensurePasswordService() {
        PasswordService service = getPasswordService();
        if (service == null) {
            String msg = "Required PasswordService has not been configured.";
            throw new IllegalStateException(msg);
        }
        return service;
    }

    protected ByteSource getSubmittedPassword(AuthenticationToken token) {
        Object credentials = token.getCredentials();
        if (credentials == null) {
            return null;
        }
        return ByteSource.Util.bytes(credentials);
    }

    protected String getStoredHashedPassword(AuthenticationInfo storedAccountInfo) {
        Object credentials = storedAccountInfo.getCredentials();
        if (credentials == null) {
            return null;
        }
        if (!(credentials instanceof String)) {
            String msg = "The stored account credentials is expected to be a String representation of a hashed password.";
            throw new IllegalArgumentException(msg);
        }
        return (String)credentials;
    }

    public PasswordService getPasswordService() {
        return passwordService;
    }

    public void setPasswordService(PasswordService passwordService) {
        this.passwordService = passwordService;
    }
}
