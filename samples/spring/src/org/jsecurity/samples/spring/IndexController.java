/*
 * Copyright (C) 2005 Jeremy C. Haile
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

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.Session;
import org.springframework.web.servlet.mvc.SimpleFormController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.validation.Errors;
import org.springframework.validation.BindException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * Description of class.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class IndexController extends SimpleFormController {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    protected Map referenceData(HttpServletRequest request, Object command, Errors errors) throws Exception {
        AuthorizationContext context = SecurityContext.getAuthorizationContext();

        boolean hasRole1 = context.hasRole( "role1" );
        boolean hasRole2 = context.hasRole( "role2" );

        Map<String,Object> refData = new HashMap<String,Object>();
        refData.put( "hasRole1", hasRole1 );
        refData.put( "hasRole2", hasRole2 );
        return refData;
    }

    protected ModelAndView onSubmit(HttpServletRequest request, HttpServletResponse response, Object obj, BindException errors) throws Exception {
        SessionValueCommand command = (SessionValueCommand) obj;

        Session session = SecurityContext.getSession();
        session.setAttribute( "value", command.getValue() );

        return super.onSubmit(request, response, command, errors);    
    }

}