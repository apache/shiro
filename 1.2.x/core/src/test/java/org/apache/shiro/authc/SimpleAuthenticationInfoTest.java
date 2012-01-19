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
package org.apache.shiro.authc;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.shiro.subject.PrincipalCollection;
import org.junit.Test;


/**
 * @since 0.9
 */
public class SimpleAuthenticationInfoTest {

    @Test
    public void testMergeWithEmptyInstances() {
        SimpleAuthenticationInfo aggregate = new SimpleAuthenticationInfo();
        SimpleAuthenticationInfo local = new SimpleAuthenticationInfo();
        aggregate.merge(local);
    }

    /**
     * Verifies fix for JSEC-122
     */
    @Test
    public void testMergeWithAggregateNullCredentials() {
        SimpleAuthenticationInfo aggregate = new SimpleAuthenticationInfo();
        SimpleAuthenticationInfo local = new SimpleAuthenticationInfo("username", "password", "testRealm");
        aggregate.merge(local);
    }
    
    @SuppressWarnings("serial")
    @Test
    public void testMergeWithImmutablePrincipalCollection() {
        SimpleAuthenticationInfo aggregate = new SimpleAuthenticationInfo();
        // Make a quick test fixture that does *not* implement MutablePrincipalCollection 
        PrincipalCollection principalCollection = new PrincipalCollection() {
	    @SuppressWarnings("unchecked")
	    public List asList() { return null;}
	    @SuppressWarnings("unchecked")
	    public Set asSet() {return null;}
	    public <T> Collection<T> byType(Class<T> type) {return null;}
	    @SuppressWarnings("unchecked")
	    public Collection fromRealm(String realmName) {
		Collection<Object> principals = new HashSet<Object>();
		principals.add("testprincipal");
		return principals;
	    }
	    public Object getPrimaryPrincipal() {return null;}
	    public Set<String> getRealmNames() {
		Set<String> realms = new HashSet<String>();
		realms.add("testrealm");
		return realms;
	    }
	    public boolean isEmpty() {return false;}
	    public <T> T oneByType(Class<T> type) {return null;}
	    @SuppressWarnings("unchecked")
	    public Iterator iterator() {return null;}
            
        };
        aggregate.setPrincipals(principalCollection);
        SimpleAuthenticationInfo local = new SimpleAuthenticationInfo("username", "password", "testRealm");
        aggregate.merge(local);
        assertEquals(2, aggregate.getPrincipals().asList().size());
    }
    
}
