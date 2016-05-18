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

package org.apache.shiro.mgt.osgi.securitymanager;

import java.util.Comparator;
import java.util.TreeSet;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionManager;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleReference;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

/**
 *
 * @author mnn
 */
@Component(name = "OSGiSecurityManager", immediate = true, service = SecurityManager.class)
public class OSGiSecurityManager extends DefaultSecurityManager{
    private Lock realmLock = new ReentrantLock();
    
    private OSGiRealmAuthorizer realmAuthorizer = new OSGiRealmAuthorizer();
    private ModularRealmAuthenticator realmAuthenticator = new ModularRealmAuthenticator();
    
    public OSGiSecurityManager() {
	super();
    }
    
    
    
    @Activate
    public void onActivate(BundleContext context){
	//setSubjectFactory(new OSGiSubjectFactory(context));
	setAuthorizer(realmAuthorizer);
	setAuthenticator(realmAuthenticator);
    }
    
    @Deactivate
    public void onDeactivate(BundleContext context){
	//setSubjectFactory(null);
	setAuthorizer(null);
	setAuthenticator(null);
    }
    
    @Reference(updated = "updatedRealm", unbind = "unbindRealm", policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.AT_LEAST_ONE)
    public void bindRealm(Realm realm){
	realmLock.lock();
	try{
	    TreeSet<Realm> realms = new TreeSet<Realm>(new BundleServiceComparator());
	    realms.add(realm);
	    setRealms(realms);
	    realmAuthorizer.setRealms(realms);
	    realmAuthenticator.setRealms(realms);
	}finally{
	    realmLock.unlock();
	}
    }
    
    public void updatedRealm(Realm realm){
	realmLock.lock();
	try{
	    TreeSet<Realm> realms = new TreeSet<Realm>(new BundleServiceComparator());
	    realms.remove(realm);
	    realms.add(realm);
	    setRealms(realms);
	    realmAuthorizer.setRealms(realms);
	    realmAuthenticator.setRealms(realms);
	}finally{
	    realmLock.unlock();
	}
    }
    
    public void unbindRealm(Realm realm){
	realmLock.lock();
	try{
	    TreeSet<Realm> realms = new TreeSet<Realm>(new BundleServiceComparator());
	    realms.remove(realm);
	    setRealms(realms);
	    realmAuthorizer.setRealms(realms);
	    realmAuthenticator.setRealms(realms);
	}finally{
	    realmLock.unlock();
	}
    }
    
    @Reference(updated = "updatedCacheManager", unbind = "unbindCacheManager", policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.OPTIONAL)
    public void bindCacheManager(CacheManager cm){
	setCacheManager(cm);
    }
    
    public void updatedCacheManager(CacheManager cm){
	setCacheManager(cm);
    }
	
    public void unbindCacheManager(CacheManager cm){
	setCacheManager(null);
    }
    
    @Reference(updated = "updatedEventBus", unbind = "unbindEventBus", policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MANDATORY)
    public void bindEventBus(EventBus eb){
	setEventBus(eb);
	
    }
    
    public void updatedEventBus(EventBus eb){
	setEventBus(eb);
    }
	
    public void unbindEventBus(EventBus eb){
	setEventBus(null);
    }
    
    @Reference(updated = "updatedRememberMeManager", unbind = "unbindRememberMeManager", policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.OPTIONAL)
    public void bindRememberMeManager(RememberMeManager rmm){
	setRememberMeManager(rmm);
	
    }
    
    public void updatedRememberMeManager(RememberMeManager rmm){
	setRememberMeManager(rmm);
    }
	
    public void unbindRememberMeManager(RememberMeManager rmm){
	setRememberMeManager(rmm);
    }
    
    @Reference(updated = "updatedSessionManager", unbind = "unbindSessionManager", policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MANDATORY)
    public void bindSessionManager(SessionManager sm){
	setSessionManager(sm);
    }
    
    public void updatedSessionManager(SessionManager sm){
	setSessionManager(sm);
    }
	
    public void unbindSessionManager(SessionManager sm){
	setSessionManager(null);
    }
    
    @Reference(updated = "updatedAuthenticationStrategy", unbind = "unbindAuthenticationStrategy", policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MANDATORY)
    public void bindAuthenticationStrategy(AuthenticationStrategy sm){
	realmAuthenticator.setAuthenticationStrategy(sm);
    }
    
    public void updatedAuthenticationStrategy(AuthenticationStrategy sm){
	realmAuthenticator.setAuthenticationStrategy(sm);
    }
	
    public void unbindAuthenticationStrategy(AuthenticationStrategy sm){
	realmAuthenticator.setAuthenticationStrategy(null);
    }
    
    @Reference(updated = "updatedSubjectFactory", unbind = "unbindSubjectFactory", policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MANDATORY, policyOption = ReferencePolicyOption.GREEDY)
    public void bindSubjectFactory(SubjectFactory sm){
	setSubjectFactory(sm);
    }
    
    public void updatedSubjectFactory(SubjectFactory sm){
	setSubjectFactory(sm);
    }
	
    public void unbindSubjectFactory(SubjectFactory sm){
	setSubjectFactory(null);
    }
    

    
    
    @Override
    protected void afterRealmsSet(){}
    @Override
    protected void afterEventBusSet(){}
    @Override
    protected void afterCacheManagerSet(){}
    @Override
    protected void afterSessionManagerSet(){}
    
    
    private class BundleServiceComparator implements Comparator<Object>{

	public int compare(Object o1, Object o2) {
	    try{
	    BundleReference object1BundleRef = (BundleReference)o1.getClass().getClassLoader();
	    BundleReference object2BundleRef = (BundleReference)o2.getClass().getClassLoader();
	    Long bundle1ID = object1BundleRef.getBundle().getBundleId();
	    Long bundle2ID = object2BundleRef.getBundle().getBundleId();
	    return bundle1ID.compareTo(bundle2ID);
	    }catch(ClassCastException ex){
		throw new IllegalArgumentException("Could not cast the classloader of o1 or o2 to a BundleReference. Are we running in an OSGi container?", ex);
	    }
	}
	
    }
    
}