/*
 * Copyright 2013 Harald Wellmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shiro.cdi.interceptor;

import static org.junit.Assert.assertEquals;

import javax.inject.Inject;

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.cdi.ShiroSecured;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.SubjectThreadState;
import org.apache.shiro.util.ThreadState;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.apache.shiro.cdi.AbstractCdiTest;

public class ShiroInterceptorTest extends AbstractCdiTest {
    
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    @Inject
    private SecuredService service;
    
    @Inject
    private SecurityManager securityManager;
    
    private ThreadState threadState;
    
    @After
    public void clearSubject() {
        if (threadState != null) {
            threadState.clear();
        }
    }

    protected void bind(Subject subject) {
        clearSubject();
        this.threadState = new SubjectThreadState(subject);
        this.threadState.bind();
    }

    protected void bindUser() {
        PrincipalCollection principals = new SimplePrincipalCollection("foo", getRealmName());
        bind(new Subject.Builder(securityManager).principals(principals).buildSubject());
    }

    protected void bindHobbit() {
        PrincipalCollection principals = new SimplePrincipalCollection("bilbo", getRealmName());
        bind(new Subject.Builder(securityManager).principals(principals).buildSubject());
    }

    protected void bindAuthenticatedUser() {
        PrincipalCollection principals = new SimplePrincipalCollection("foo", getRealmName());
        bind(new Subject.Builder(securityManager).
                principals(principals).authenticated(true).buildSubject());
    }
    
    @Test
    public void guest() {
        assertEquals("hi foo", service.simple("foo"));
        
        thrown.expect(UnauthenticatedException.class);
        service.authentication("foo");
    }

    @Test
    public void role() {
        bindUser();
        assertEquals("hi foo", service.role("foo"));
    }

    @Test
    public void missingRole() {
        bindHobbit();
        
        thrown.expect(UnauthorizedException.class);
        service.role("foo");
    }

    @Test
    public void permission() {
        bindUser();
        assertEquals("hi foo", service.permission("foo"));
    }

    @Test
    public void ḿissingPermission() {
        bindHobbit();
        
        thrown.expect(UnauthorizedException.class);
        service.permission("foo");
    }

    @Test
    public void authentication() {
        bindAuthenticatedUser();
        assertEquals("hi foo", service.authentication("foo"));
        
        thrown.expect(UnauthenticatedException.class);
        service.simple("foo");
        
    }

    @Test
    public void user() {
        bindUser();
        assertEquals("hi foo", service.user("foo"));
    }

    @ShiroSecured
    public static class SecuredService {
        @RequiresGuest
        public String simple(final String name) {
            return "hi " + name;
        }

        @RequiresRoles({"role"})
        public String role(final String name) {
            return "hi " + name;
        }

        @RequiresPermissions({"permission"})
        public String permission(final String name) {
            return "hi " + name;
        }

        @RequiresAuthentication
        public String authentication(final String name) {
            return "hi " + name;
        }

        @RequiresUser
        public String user(final String name) {
            return "hi " + name;
        }
    }
}
