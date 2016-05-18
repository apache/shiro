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

package org.apache.shiro.mgt.osgi.sessionmanager;

import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionFactory;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

/**
 *
 * @author mnn
 */
@Component(name = "OSGiDefaultSessionManager", service = SessionManager.class)
public class OSGiDefaultSessionManager extends DefaultSessionManager{
    
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
    
    @Reference(updated = "updatedSessionDAO", unbind = "unbindSessionDAO", policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MANDATORY)
    public void bindSessionDAO(SessionDAO sdao){
	setSessionDAO(sdao);
    }
    
    public void updatedSessionDAO(SessionDAO sdao){
	setSessionDAO(sdao);
    }
	
    public void unbindSessionDAO(SessionDAO sdao){
	setSessionDAO(null);
    }
    
    @Reference(updated = "updatedSessionFactory", unbind = "unbindSessionFactory", policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MANDATORY)
    public void bindSessionFactory(SessionFactory sf){
	setSessionFactory(sf);
    }
    
    public void updatedSessionFactory(SessionFactory sf){
	setSessionFactory(sf);
    }
	
    public void unbindSessionFactory(SessionFactory sf){
	setSessionFactory(null);
    }
    
    
    
    @Override
    public void setSessionDAO(SessionDAO sessionDAO) {
        this.sessionDAO = sessionDAO;
    }
}
