/*
 * Copyright 2005-2008 Jeremy Haile
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
package org.jsecurity.samples.spring.web;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.mgt.DefaultSecurityManager;
import org.jsecurity.subject.Subject;
import org.springframework.validation.BindException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.SimpleFormController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Spring MVC controller responsible for authenticating the user.
 *
 * @author Jeremy Haile
 * @since 0.1
 */
public class LoginController extends SimpleFormController {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private DefaultSecurityManager securityManager;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Sets the security manager that should be used to login the user.
     *
     * @param securityManager the security manager used to perform the login.
     */

    public void setSecurityManager(DefaultSecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    protected ModelAndView onSubmit(HttpServletRequest request, HttpServletResponse response, Object cmd, BindException errors) throws Exception {

        LoginCommand command = (LoginCommand) cmd;

        UsernamePasswordToken token = new UsernamePasswordToken(command.getUsername(), command.getPassword());

        securityManager.init();

        try {
           Subject subject = securityManager.login(token);
        } catch (AuthenticationException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Error authenticating.", e);
            }
            errors.reject("error.invalidLogin", "The username or password was not correct.");
        }

        if (errors.hasErrors()) {
            return showForm(request, response, errors);
        } else {
            return new ModelAndView(getSuccessView());
        }
    }
}