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

package org.apache.shiro.mgt.osgi.configadminrealm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.Set;
import java.util.TreeSet;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleRole;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author mnn
 */
@Component(name = "ConfigurationAdminRealm", configurationPid = "org.apache.shiro.realm.configadminrealm", configurationPolicy = ConfigurationPolicy.OPTIONAL, immediate = true, service = {Realm.class, Authorizer.class})
@Designate(ocd = ConfigAdminRealmOCD.class)
public class ConfigurationAdminRealm extends SimpleAccountRealm{
    private static final Logger logger = LoggerFactory.getLogger(ConfigurationAdminRealm.class);
    ComponentContext context;

    public ConfigurationAdminRealm() {
	this.setRolePermissionResolver(new RolePermissionResolver() {

	    public Collection<Permission> resolvePermissionsInRole(String roleString) {
		ConfigurationAdminRealm.this.ROLES_LOCK.readLock().lock();
		try{
		    SimpleRole role = roles.get(roleString);
		    if(role == null){
			return new ArrayList<Permission>();
		    }
		    return role.getPermissions();
		}finally{
		    ConfigurationAdminRealm.this.ROLES_LOCK.readLock().unlock();
		}
	    }
	});
    }
    
    
    
    protected void updateUsersAndRoles(Dictionary<String, Object> configuration){
	clearUsersAndRoles();
	if(configuration == null || configuration.isEmpty()){
	    logger.info("Updated users and roles with emtpy configuration. Clearing data.");
	    return;
	}
	
	if(logger.isDebugEnabled()){
	    logger.debug("Configuration updated with items:");
	    Enumeration values= configuration.elements();
	    while(values.hasMoreElements()){
		Object value = values.nextElement();
		if(value instanceof String[]){
		    logger.debug(Arrays.asList((String[])value)+"");
		}else{
		    logger.debug(value+"");
		}
		
	    }
	}
	
	
	logger.info("Updating users and roles");
	for(String user : getStringList(configuration.get("user"))){
	    int userSeperator = user.indexOf("/");
	    int firstRoleSeperator = user.indexOf(",");
	    String username = user.substring(0, user.indexOf("/")).replaceAll("\\s", "");
	    String password = firstRoleSeperator >= 0 ? user.substring(userSeperator+1, firstRoleSeperator) : user.substring(userSeperator+1);
	    String[] stringRoles = user.split(",");
	    if(stringRoles.length > 1){
		stringRoles = Arrays.copyOfRange(stringRoles, 1, stringRoles.length);
	    }else{
		stringRoles = new String[0];
	    }
	    addAccount(username, password, stringRoles);
	    if(logger.isDebugEnabled()){
		logger.debug("Adding account "+username+" with password "+password.replace(".","#")+" and roles "+Arrays.toString(stringRoles));
	    }
	}
	
	for(String role : getStringList(configuration.get("role"))){
	    String[] splitRole = role.split("/");
	    String roleName = splitRole[0];
	    Set<Permission> permissions = new TreeSet<Permission>(new WildcardPermissionComparator());
	    if(splitRole.length > 1){
		String[] stringRoles = splitRole[1].split(",");
		stringRoles = Arrays.copyOfRange(stringRoles, 0, stringRoles.length);	
		for(String rolesString : stringRoles){
		    permissions.add(new WildcardPermission(rolesString));
		}
	    }
	    if(logger.isDebugEnabled()){
		logger.debug("Adding role "+roleName+" with permissions "+permissions);
	    }
	    add(new SimpleRole(roleName, permissions));
	}
	if(logger.isInfoEnabled()){
	    USERS_LOCK.readLock().lock();
	    ROLES_LOCK.readLock().lock();
	    try{
	    logger.info("Accounts updated: ");
	    for(SimpleAccount account : users.values()){
		logger.info("User: '"+account.toString()+"' "+account.getRoles());
	    }
	    for(SimpleRole role : roles.values()){
		logger.info("Role: '"+role.toString()+"' "+role.getPermissions());
	    }
	    }finally{
		USERS_LOCK.readLock().unlock();
		ROLES_LOCK.readLock().unlock();
	    }
	}
    }
    
    protected String[] getStringList(Object configurationItem){
	if(configurationItem instanceof String[]){
	    return (String[])configurationItem;
	}else if(configurationItem instanceof String){
	    return new String[]{(String)configurationItem};
	}else{
	    return new String[0];
	}
	
    }
    
    protected void clearUsersAndRoles(){
	ROLES_LOCK.writeLock().lock();
	try{
	    users.clear();
	    roles.clear();
	}finally{
	    ROLES_LOCK.writeLock().unlock();
	}
	
    }
    @Activate
    void activate(ComponentContext ctx) {
	context = ctx;
	updateUsersAndRoles(ctx.getProperties());
    }

    @Modified
    void modified(ComponentContext ctx) {
	context = ctx;
	updateUsersAndRoles(ctx.getProperties());
    }

    @Deactivate
    void deactivate(ComponentContext ctx) {
	context = ctx;
	clearUsersAndRoles();
    }
    
    private class WildcardPermissionComparator implements Comparator<Permission>{

	public WildcardPermissionComparator() {
	}

	public int compare(Permission o1, Permission o2) {
	    return o1.toString().compareTo(o2.toString());
	}
	
	
    }
    
}
