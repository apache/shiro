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
import org.apache.shiro.crypto.hash.Hash;

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

    public PasswordMatcher() {
        this.passwordService = new DefaultPasswordService();
    }

    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {

        PasswordService service = ensurePasswordService();

        Object submittedPassword = getSubmittedPassword(token);
        Object storedCredentials = getStoredPassword(info);
        assertStoredCredentialsType(storedCredentials);

        if (storedCredentials instanceof Hash) {
            Hash hashedPassword = (Hash)storedCredentials;
            HashingPasswordService hashingService = assertHashingPasswordService(service);
            return hashingService.passwordsMatch(submittedPassword, hashedPassword);
        }
        //otherwise they are a String (asserted in the 'assertStoredCredentialsType' method call above):
        String formatted = (String)storedCredentials;
        return passwordService.passwordsMatch(submittedPassword, formatted);
    }

    private HashingPasswordService assertHashingPasswordService(PasswordService service) {
        if (service instanceof HashingPasswordService) {
            return (HashingPasswordService) service;
        }
        String msg = "AuthenticationInfo's stored credentials are a Hash instance, but the " +
                "configured passwordService is not a " +
                HashingPasswordService.class.getName() + " instance.  This is required to perform Hash " +
                "object password comparisons.";
        throw new IllegalStateException(msg);
    }

    private PasswordService ensurePasswordService() {
        PasswordService service = getPasswordService();
        if (service == null) {
            String msg = "Required PasswordService has not been configured.";
            throw new IllegalStateException(msg);
        }
        return service;
    }

    protected Object getSubmittedPassword(AuthenticationToken token) {
        return token != null ? token.getCredentials() : null;
    }

    private void assertStoredCredentialsType(Object credentials) {
        if (credentials instanceof String || credentials instanceof Hash) {
            return;
        }

        String msg = "Stored account credentials are expected to be either a " +
                Hash.class.getName() + " instance or a formatted hash String.";
        throw new IllegalArgumentException(msg);
    }

    protected Object getStoredPassword(AuthenticationInfo storedAccountInfo) {
        Object stored = storedAccountInfo != null ? storedAccountInfo.getCredentials() : null;
        //fix for https://issues.apache.org/jira/browse/SHIRO-363
        if (stored instanceof char[]) {
            stored = new String((char[])stored);
        }
        return stored;
    }

    public PasswordService getPasswordService() {
        return passwordService;
    }

    public void setPasswordService(PasswordService passwordService) {
        this.passwordService = passwordService;
    }
}
