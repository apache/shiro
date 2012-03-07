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
package org.apache.shiro.authc.pam;

import org.apache.shiro.authc.AuthenticationInfo;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Tests for {@code FirstSuccessfulStrategy}
 * @since 1.3
 */
public class FirstSuccessfulStrategyTest
{

    private FirstSuccessfulStrategy strategy;

    @Before
    public void setUp() {
        strategy = new FirstSuccessfulStrategy();
    }

    @Test
    public void beforeAllAttempts() {
        AuthenticationInfo info = strategy.beforeAllAttempts(null, null);
        assertNull( info );
    }

    @Test
    public void afterAttempt() {
        
        AuthenticationInfo authInfo = createNiceMock(AuthenticationInfo.class);
        AuthenticationInfo otherAuthInfo = createNiceMock(AuthenticationInfo.class);
        
        // same auth info for both the singleRealmInfo and the aggregate
        assertFalse(strategy.continueAfterAttempt(authInfo, authInfo, null));
        
        // both null
        assertTrue(strategy.continueAfterAttempt(null, null, null));
        
        // singleRealm not null, aggregate null (not valid condition, but make sure it returns true)
        assertTrue(strategy.continueAfterAttempt(authInfo, null, null));

        // single realm null, aggregate not null (the ModularRealmAuthenticator will not get into this state)
        assertTrue(strategy.continueAfterAttempt(null, authInfo, null));
        
        // single realm and aggregate have different authInfo
        assertTrue(strategy.continueAfterAttempt(authInfo, otherAuthInfo, null));
    }
}
