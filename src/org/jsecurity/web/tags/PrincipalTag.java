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

package org.jsecurity.web.tags;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspTagException;
import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.IOException;
import java.security.Principal;

/**
 * <p>Tag used to print out the String value of a user's default principal,
 * or a specific principal as specified by the tag's attributes.</p>
 *
 * <p> If no attributes are specified, the tag prints out the <tt>toString()</tt>
 * value of the user's default principal.  If the <tt>type</tt> attribute
 * is specified, the tag looks for a principal with the given type.  If the
 * <tt>property</tt> attribute is specified, the tag prints the string value of
 * the specified property of the principal.  If no principal is found or the user
 * is not authenticated, the tag displays nothing unless a <tt>defaultValue</tt>
 * is specified.</p>
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class PrincipalTag extends SecureTag {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());

    /**
     * The type of principal to be retrieved, or null if the default principal should be used.
     */
    private Class type;

    /**
     * The property name to retrieve of the principal, or null if the <tt>toString()</tt> value should be used.
     */
    private String property;

    /**
     * The default value that should be displayed if the user is not authenticated, or no principal is found.
     */
    private String defaultValue;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/


    public Class getType() {
        return type;
    }


    public void setType(Class type) {
        this.type = type;
    }


    public String getProperty() {
        return property;
    }


    public void setProperty(String property) {
        this.property = property;
    }


    public String getDefaultValue() {
        return defaultValue;
    }


    public void setDefaultValue(String defaultValue) {
        this.defaultValue = defaultValue;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    public int onDoStartTag() throws JspException {
        String strValue = null;

        if( getSecurityContext().isAuthenticated() ) {

            // Get the principal to print out
            Principal principal = null;
            if( type == null ) {
                principal = getSecurityContext().getPrincipal();
            } else {
                principal = getSecurityContext().getPrincipalByType( type );
            }

            // Get the string value of the principal
            if( principal != null ) {
                if( property == null ) {
                    strValue = principal.toString();
                } else {
                    strValue = getPrincipalProperty( principal, property );
                }
            }

        }

        // Print out the principal value if not null
        if( strValue != null ) {
            try {
                pageContext.getOut().write( strValue );
            } catch (IOException e) {
                throw new JspTagException( "Error writing [" + strValue + "] to JSP.", e );
            }
        }

        return SKIP_BODY;
    }


    private String getPrincipalProperty(Principal principal, String property) throws JspTagException {
        String strValue = null;

        try {
            BeanInfo bi = Introspector.getBeanInfo( principal.getClass() );

            // Loop through the properties to get the string value of the specified property
            boolean foundProperty = false;
            for( PropertyDescriptor pd : bi.getPropertyDescriptors() ) {
                if( pd.getName().equals( property ) ) {
                    Object value = pd.getReadMethod().invoke( principal, (Object[]) null );
                    strValue = String.valueOf( value );
                    foundProperty = true;
                    break;
                }
            }

            if( !foundProperty ) {
                final String message = "Property [" + property + "] not found in principal of type [" + principal.getClass().getName() + "]";
                if (logger.isErrorEnabled()) {
                    logger.error(message);
                }
                throw new JspTagException( message );
            }

        } catch (Exception e) {
            final String message = "Error reading property [" + property + "] from principal of type [" + principal.getClass().getName() + "]";
            if (logger.isErrorEnabled()) {
                logger.error(message, e);
            }
            throw new JspTagException( message, e );
        }

        return strValue;
    }
}