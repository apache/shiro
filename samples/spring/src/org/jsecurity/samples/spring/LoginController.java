/*
 * Copyright (C) 2005 Jeremy Haile
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */

package org.jsecurity.samples.spring;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authc.UsernamePasswordToken;
import org.springframework.validation.BindException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.SimpleFormController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Description of class.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class LoginController extends SimpleFormController {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private Authenticator authenticator;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    protected ModelAndView onSubmit(HttpServletRequest request, HttpServletResponse response, Object cmd, BindException errors) throws Exception {

        LoginCommand command = (LoginCommand) cmd;

        UsernamePasswordToken token = new UsernamePasswordToken( command.getUsername(), command.getPassword() );
        try {
            authenticator.authenticate( token );
        } catch (AuthenticationException e) {
            errors.reject( "error.invalidLogin", "The username or password was not correct." );
        }

        if( errors.hasErrors() ) {
            return showForm( request, response, errors );
        } else {
            return new ModelAndView( getSuccessView() );
        }
    }
}