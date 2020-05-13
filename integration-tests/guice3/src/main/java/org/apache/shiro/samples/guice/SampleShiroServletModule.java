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
package org.apache.shiro.samples.guice;

import com.google.inject.Provides;
import com.google.inject.binder.AnnotatedBindingBuilder;
import com.google.inject.name.Names;
import org.apache.shiro.lang.codec.Base64;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.guice.web.ShiroWebModule;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;

import javax.inject.Singleton;
import javax.servlet.ServletContext;
import java.net.MalformedURLException;
import java.net.URL;

public class SampleShiroServletModule extends ShiroWebModule {
    private final ServletContext servletContext;

    public SampleShiroServletModule(ServletContext servletContext) {
        super(servletContext);

        this.servletContext = servletContext;
    }

    @Override
    protected void configureShiroWeb() {
        bindConstant().annotatedWith(Names.named("shiro.loginUrl")).to("/login.jsp");
        try {
            this.bindRealm().toConstructor(IniRealm.class.getConstructor(Ini.class));
        } catch (NoSuchMethodException e) {
            addError("Could not locate proper constructor for IniRealm.", e);
        }

        this.addFilterChain("/login.jsp", AUTHC);
        this.addFilterChain("/logout", LOGOUT);
        this.addFilterChain("/account/**", AUTHC);

        this.addFilterChain("/remoting/**", AUTHC, config(ROLES, "b2bClient"), config(PERMS, "remote:invoke:lan,wan"));
    }

    @Provides
    @Singleton
    Ini loadShiroIni() throws MalformedURLException {
        URL iniUrl = servletContext.getResource("/WEB-INF/shiro.ini");
        return Ini.fromResourcePath("url:" + iniUrl.toExternalForm());
    }

    @Override
    protected void bindWebSecurityManager(AnnotatedBindingBuilder<? super WebSecurityManager> bind)
    {
        try
        {
            String cipherKey = loadShiroIni().getSectionProperty( "main", "securityManager.rememberMeManager.cipherKey" );

            DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
            CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
            rememberMeManager.setCipherKey( Base64.decode( cipherKey ) );
            securityManager.setRememberMeManager(rememberMeManager);
            bind.toInstance(securityManager);
        }
        catch ( MalformedURLException e )
        {
            // for now just throw, you could just call
            // super.bindWebSecurityManager(bind) if you do not need rememberMe functionality
            throw new ConfigurationException( "securityManager.rememberMeManager.cipherKey must be set in shiro.ini." );
        }


    }
}
