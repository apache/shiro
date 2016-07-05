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

package org.ops4j.pax.shiro.cdi.config;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;


@RunWith(PaxExam.class)
public class CdiIniSecurityManagerFactoryTest {

    
    @Inject
    private BeanManager beanManager;
    
    @Inject
    private Subject subject;
    
    @Test
    public void getShiroBeanFromIni() {
        CdiIniSecurityManagerFactory securityManagerFactory = new CdiIniSecurityManagerFactory("classpath:test-shiro.ini", beanManager);
        SecurityManager securityManager = securityManagerFactory.createInstance();
        assertThat(securityManager, is(notNullValue()));
        Object passwordMatcher = securityManagerFactory.getBeans().get("passwordMatcher");
        assertThat(passwordMatcher, is(instanceOf(PasswordMatcher.class)));
    }

    @Test
    public void getCdiBeanFromIni() {
        CdiIniSecurityManagerFactory securityManagerFactory = new CdiIniSecurityManagerFactory("classpath:test-shiro-cdi.ini", beanManager);
        DefaultSecurityManager securityManager = (DefaultSecurityManager) securityManagerFactory.createInstance();
        assertThat(securityManager, is(notNullValue()));
        
        SecurityUtils.setSecurityManager(securityManager);
        Object passwordMatcher = securityManagerFactory.getBeans().get("myPasswordMatcher");
        assertThat(passwordMatcher, is(instanceOf(MyPasswordMatcher.class)));
        IniRealm realm = (IniRealm) securityManager.getRealms().iterator().next();
        assertThat(realm.getCredentialsMatcher(), is(instanceOf(MyPasswordMatcher.class)));
        Subject subject = SecurityUtils.getSubject();
        assertThat(subject, is(notNullValue()));
        assertThat(subject.getPrincipal(), is(nullValue()));
        assertThat(subject.isAuthenticated(), is(false));
        UsernamePasswordToken token = new UsernamePasswordToken("admin", "secret");
        subject.login(token);
        assertThat(subject.isAuthenticated(), is(true));
        
        subject.logout();
        assertThat(subject.isAuthenticated(), is(false));
    }
    
    @Test
    public void checkInjectedSubject() {
        CdiIniSecurityManagerFactory securityManagerFactory = new CdiIniSecurityManagerFactory("classpath:test-shiro-cdi.ini", beanManager);
        DefaultSecurityManager securityManager = (DefaultSecurityManager) securityManagerFactory.createInstance();
        assertThat(securityManager, is(notNullValue()));        
        SecurityUtils.setSecurityManager(securityManager);
        
        assertThat(subject, is(notNullValue()));
        assertThat(subject.getPrincipal(), is(nullValue()));
        assertThat(subject.isAuthenticated(), is(false));
        UsernamePasswordToken token = new UsernamePasswordToken("admin", "secret");
        subject.login(token);
        assertThat(subject.isAuthenticated(), is(true));
        
        subject.logout();
        assertThat(subject.isAuthenticated(), is(false));
    }
    
}
