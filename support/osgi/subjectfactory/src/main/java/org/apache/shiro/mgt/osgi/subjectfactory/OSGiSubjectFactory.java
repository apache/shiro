/*
 * Copyright 2016 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shiro.mgt.osgi.subjectfactory;

import org.apache.shiro.mgt.DefaultSubjectFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.apache.shiro.util.OSGiAdapter;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;

/**
 *
 * @author mnn
 */
@Component(name = "OSGiSecurityManager", service = SubjectFactory.class, immediate = true)
public class OSGiSubjectFactory extends DefaultSubjectFactory implements SubjectFactory{
    BundleContext bundleContext;

    public OSGiSubjectFactory(BundleContext context) {
	this.bundleContext = context;
    }

    public OSGiSubjectFactory() {
    }
    
    @Activate
    public void activate(BundleContext bundleContext){
	this.bundleContext = bundleContext;
    }
    
    @Override
    protected Subject newSubjectInstance(PrincipalCollection principals, boolean authenticated, String host, Session session, SecurityManager securityManager) {
	return new DelegatingSubject(principals, authenticated, host, session, true, new OSGiAdapter<SecurityManager>(bundleContext, bundleContext.getServiceReference(SecurityManager.class)), securityManager);
    }

    @Override
    public Subject createSubject(SubjectContext context) {
	
        SecurityManager securityManager = context.resolveSecurityManager();
        Session session = context.resolveSession();
        boolean sessionCreationEnabled = context.isSessionCreationEnabled();
        PrincipalCollection principals = context.resolvePrincipals();
        boolean authenticated = context.resolveAuthenticated();
        String host = context.resolveHost();

        return new DelegatingSubject(principals, authenticated, host, session, sessionCreationEnabled, new OSGiAdapter<SecurityManager>(bundleContext, bundleContext.getServiceReference(SecurityManager.class)), securityManager);
    }
    
    
    
}
