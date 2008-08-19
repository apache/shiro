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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.SecurityUtils;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.mgt.DefaultSecurityManager;
import org.jsecurity.session.Session;
import org.jsecurity.subject.Subject;

/**
 * @author Les Hazlewood
 * @since 0.9 RC2
 */
public class Quickstart {

    private static final transient Log log = LogFactory.getLog(Quickstart.class);


    public static void main( String[] args ) {

        //Most applications would never instantiate a SecurityManager directly - you would instead configure
        //JSecurity in web.xml or a container (JEE, Spring, etc).
        //But, since this is a quickstart, we just want you to get a feel for how the JSecurity API looks, so this
        //is sufficient to have a simple working example:
        DefaultSecurityManager securityManager = new DefaultSecurityManager();

        //for this simple example quickstart, make the SecurityManager accessible across the JVM.  Most
        //applications wouldn't do this and instead rely on their container configuration or web.xml for webapps.  That
        //is outside the scope of this simple quickstart, so we'll just do the bare minimum so you can continue to
        //get a feel for things.
        SecurityUtils.setSecurityManager( securityManager );


        //now that a simple JSecurity environment is set up, let's see what you can do:

        //get the currently executing user:
        Subject currentUser = SecurityUtils.getSubject();

        //Do some stuff with a Session (no need for a web or EJB container!!!)
        Session session = currentUser.getSession();
        session.setAttribute( "someKey", "aValue" );
        String value = (String)session.getAttribute("someKey");
        if ( value.equals( "aValue" ) ) {
            System.out.println("Retrieved the correct value!");
        }


        //let's log in the current user so we can check against roles and permissions:
        if ( !currentUser.isAuthenticated() ) {
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa" );
            token.setRememberMe(true);
            currentUser.login(token);
        }

        //test a role:
        if ( currentUser.hasRole( "schwartz" ) ) {
            System.out.println("May the Schwartz be with you!" );
        } else {
            System.out.println("A mere mortal.");
        }

        //test a typed permission (not instance-level)
        if ( currentUser.isPermitted( "lightsaber:weild" ) ) {
            System.out.println("You may use a lightsaber ring.  Use it wisely.");
        } else {
            System.out.println("Sorry, lightsaber rings are for schwartz masters only.");
        }

        //a (very powerful) Instance Level permission:
        if ( currentUser.isPermitted( "winnebago:drive:eagle5" ) ) {
            System.out.println("You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  " +
                    "Here are the keys - have fun!");
        } else {
            System.out.println("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        //all done - log out!
        currentUser.logout();

        System.exit(0);
    }
}
