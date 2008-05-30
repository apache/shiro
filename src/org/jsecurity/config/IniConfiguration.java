/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.config;

import org.jsecurity.io.IniResource;
import org.jsecurity.mgt.DefaultSecurityManager;
import org.jsecurity.mgt.RealmSecurityManager;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.realm.Realm;
import org.jsecurity.realm.RealmFactory;
import org.jsecurity.util.LifecycleUtils;
import org.jsecurity.util.ResourceUtils;

import java.io.InputStream;
import java.io.Reader;
import java.util.*;

/**
 * @since 0.9
 * @author Les Hazlewood
 */
public class IniConfiguration extends TextConfiguration {

    public static final String DEFAULT_INI_RESOURCE_PATH = "classpath:jsecurity.ini";
   
    public static final String MAIN = "main";
    public static final String INTERCEPTORS = "interceptors";
    public static final String URLS = "urls";

    public static final String SESSION_MODE_PROPERTY_NAME = "sessionMode";

    protected IniResource iniResource = null;

    public IniConfiguration() {
        if ( ResourceUtils.resourceExists( DEFAULT_INI_RESOURCE_PATH ) ) {
            load(DEFAULT_INI_RESOURCE_PATH);
        }
        //else defaults are fine
    }

    public IniConfiguration(String configBodyOrResourcePath) {
        load(configBodyOrResourcePath);
    }

    public IniConfiguration(String configBodyOrResourcePath, String charsetName) {
        try {
            this.iniResource = new IniResource(configBodyOrResourcePath, charsetName);
            process(this.iniResource);
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
    }

    protected void load(Reader r) throws ConfigurationException {
        try {
            this.iniResource = new IniResource(r);
            process(this.iniResource);
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
    }

    protected void load(Scanner s) throws ConfigurationException {
        try {
            this.iniResource = new IniResource(s);
            process(this.iniResource);
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
    }

    public void load(String path) throws ConfigurationException {
        try {
            this.iniResource = new IniResource(path);
            process(this.iniResource);
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
    }

    public void load(InputStream is) throws ConfigurationException {
        try {
            this.iniResource = new IniResource(is);
            process(this.iniResource);
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
    }

    protected void process( IniResource ini ) {
        processIni( ini.getSections() );
    }

    protected void processIni( Map<String,Map<String,String>> sections ) {
        SecurityManager securityManager = createSecurityManager( sections );
        if ( securityManager == null ) {
            String msg = "A " + SecurityManager.class + " instance must be created at startup.";
            throw new ConfigurationException( msg );
        }
        setSecurityManager( securityManager );

        afterSecurityManagerSet( sections );
    }

    protected SecurityManager createSecurityManager( Map<String,Map<String,String>> sections ) {
        Map<String,String> mainSection = sections.get( MAIN );
        return doCreateSecurityManager( mainSection );
    }

    protected RealmSecurityManager newSecurityManagerInstance() {
        return new DefaultSecurityManager();
    }

    protected SecurityManager doCreateSecurityManager( Map<String,String> mainSection ) {

        Map<String,Object> defaults = new LinkedHashMap<String,Object>();

        RealmSecurityManager securityManager = newSecurityManagerInstance();
        defaults.put( "securityManager", securityManager );
        ReflectionBuilder builder = new ReflectionBuilder(defaults);
        Map<String,Object> objects = builder.buildObjects(mainSection);

        //realms and realm factory might have been created - pull them out first so we can
        //initialize the securityManager:

        List<Realm> realms = new ArrayList<Realm>();

        //iterate over the map entries to pull out the realm factory(s):

        for( Map.Entry<String,Object> entry : objects.entrySet() ) {
            String name = entry.getKey();
            Object value = entry.getValue();
            if ( value instanceof RealmFactory ) {
                RealmFactory factory = (RealmFactory)value;
                LifecycleUtils.init(factory);
                Collection<Realm> factoryRealms = factory.getRealms();
                if ( factoryRealms != null && !factoryRealms.isEmpty() ) {
                    realms.addAll( factoryRealms );
                }
            } else if ( value instanceof Realm ) {
                Realm realm = (Realm)value;
                //set the name if null:
                String existingName = realm.getName();
                if ( existingName == null || existingName.startsWith( realm.getClass().getName() ) ) {
                    try {
                        builder.applyProperty( realm, "name", name );
                    } catch ( Exception ignored ) {}
                }
                realms.add( realm );
            }
        }

        //set them on the SecurityManager
        if ( !realms.isEmpty() ) {
            securityManager.setRealms(realms);
        }

        securityManager.init();

        LifecycleUtils.init(realms);

        return securityManager;
    }

    protected void afterSecurityManagerSet( Map<String,Map<String,String>> sections ) {}
}
