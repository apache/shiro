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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.ki.SecurityUtils;
import org.apache.ki.mgt.DefaultSecurityManager;
import org.apache.ki.session.Session;
import org.apache.ki.subject.Subject;

import org.apache.ki.authc.AuthenticationException;
import org.apache.ki.authc.IncorrectCredentialsException;
import org.apache.ki.authc.LockedAccountException;
import org.apache.ki.authc.UnknownAccountException;
import org.apache.ki.authc.UsernamePasswordToken;


/**
 * @author Les Hazlewood
 * @since 0.9 RC2
 */
public class Quickstart {

    private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);


    public static void main( String[] args ) {

        //Most applications would never instantiate a SecurityManager directly - you would instead configure
        //Ki in web.xml or a container (JEE, Spring, etc).
        //But, since this is a quickstart, we just want you to get a feel for how the Ki API looks, so this
        //is sufficient to have a simple working example:
        DefaultSecurityManager securityManager = new DefaultSecurityManager();

        //for this simple example quickstart, make the SecurityManager accessible across the JVM.  Most
        //applications wouldn't do this and instead rely on their container configuration or web.xml for webapps.  That
        //is outside the scope of this simple quickstart, so we'll just do the bare minimum so you can continue to
        //get a feel for things.
        SecurityUtils.setSecurityManager( securityManager );


        //now that a simple Ki environment is set up, let's see what you can do:

        //get the currently executing user:
        Subject currentUser = SecurityUtils.getSubject();

        //Do some stuff with a Session (no need for a web or EJB container!!!)
        Session session = currentUser.getSession();
        session.setAttribute( "someKey", "aValue" );
        String value = (String)session.getAttribute("someKey");
        if ( value.equals( "aValue" ) ) {
            log.info( "Retrieved the correct value! [" + value + "]" );
        }


        //let's log in the current user so we can check against roles and permissions:
        if ( !currentUser.isAuthenticated() ) {
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa" );
            token.setRememberMe(true);
            try {
                currentUser.login(token);
            } catch (UnknownAccountException uae) {
                log.info( "There is no user with username of " + token.getPrincipal() );
            } catch ( IncorrectCredentialsException ice ) {
                log.info("Password for account " + token.getPrincipal() + " was incorrect!");
            } catch ( LockedAccountException lae ) {
                log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                         "Please contact your administrator to unlock it.");
            }
            // ... catch more exceptions here (maybe custom ones specific to your application?
            catch ( AuthenticationException ae ) {
                //unexpected condition?  error?
            }
        }

        //say who they are:
        //print their identifying principal (in this case, a username):
        log.info( "User [" + currentUser.getPrincipal() + "] logged in successfully." );

        //test a role:
        if ( currentUser.hasRole( "schwartz" ) ) {
            log.info("May the Schwartz be with you!" );
        } else {
            log.info( "Hello, mere mortal." );
        }

        //test a typed permission (not instance-level)
        if ( currentUser.isPermitted( "lightsaber:weild" ) ) {
            log.info("You may use a lightsaber ring.  Use it wisely.");
        } else {
            log.info("Sorry, lightsaber rings are for schwartz masters only.");
        }

        //a (very powerful) Instance Level permission:
        if ( currentUser.isPermitted( "winnebago:drive:eagle5" ) ) {
            log.info("You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  " +
                     "Here are the keys - have fun!");
        } else {
            log.info("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        //all done - log out!
        currentUser.logout();

        System.exit(0);
    }
}
