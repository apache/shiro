/*
 * Copyright 2008 Les Hazlewood
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
package org.jsecurity.samples.sprhib.security;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authz.AuthorizingAccount;
import org.jsecurity.realm.AuthorizingRealm;
import org.jsecurity.samples.sprhib.party.eis.UserDAO;
import org.jsecurity.subject.PrincipalCollection;
import org.springframework.beans.factory.InitializingBean;

/**
 * The Spring/Hibernate sample application's one and only configured JSecurity Realm.
 *
 * <p>Because a Realm is really just a security-specific DAO, we could have just made Hibernate calls directly
 * in the implementation and named it a 'HibernateRealm' or something similar.</p>
 *
 * <p>But we've decided to make the calls to the database using a UserDAO, since a DAO would be used in other areas
 * of a 'real' application in addition to here. We felt it better to use that same DAO to show code re-use.
 * That is, in a real app, there is no need to duplicate Hibernate calls in the Realm implementation if you've already
 * got a User DAO (as most apps would).  So, we just use that UserDAO here.</p>
 *
 * @author Les Hazlewood
 */
public class DefaultRealm extends AuthorizingRealm implements InitializingBean {

    protected UserDAO userDAO = null;

    public DefaultRealm() {
        setName("DefaultRealm"); //This name must match the name in the User class's getPrincipals() method
    }

    public void setUserDAO(UserDAO userDAO) {
        this.userDAO = userDAO;
    }

    public void afterPropertiesSet() throws Exception {
        if ( this.userDAO == null ) {
            throw new IllegalStateException( "UserDAO property was not injected.  Please check your Spring config." );
        }
    }

    protected Account doGetAccount(AuthenticationToken authcToken) throws AuthenticationException {
        UsernamePasswordToken token = (UsernamePasswordToken)authcToken;
        return userDAO.findUser( token.getUsername() );
    }


    protected AuthorizingAccount doGetAccount(PrincipalCollection principals) {
        String username = (String)principals.fromRealm( getName() ).iterator().next();
        return userDAO.findUser( username );
    }

}

