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
package org.apache.shiro.web.tags;

import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.IOException;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspTagException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 */
public class PrincipalTag extends SecureTag {

    //TODO - complete JavaDoc

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private static final Logger log = LoggerFactory.getLogger(PrincipalTag.class);

    /**
     * The type of principal to be retrieved, or null if the default principal should be used.
     */
    private String type;

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


    public String getType() {
        return type;
    }


    public void setType(String type) {
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


    @SuppressWarnings({"unchecked"})
    public int onDoStartTag() throws JspException {
        String strValue = null;

        if (getSubject() != null) {

            // Get the principal to print out
            Object principal;

            if (type == null) {
                principal = getSubject().getPrincipal();
            } else {
                principal = getPrincipalFromClassName();
            }

            // Get the string value of the principal
            if (principal != null) {
                if (property == null) {
                    strValue = principal.toString();
                } else {
                    strValue = getPrincipalProperty(principal, property);
                }
            }

        }

        // Print out the principal value if not null
        if (strValue != null) {
            try {
                pageContext.getOut().write(strValue);
            } catch (IOException e) {
                throw new JspTagException("Error writing [" + strValue + "] to JSP.", e);
            }
        }

        return SKIP_BODY;
    }

    @SuppressWarnings({"unchecked"})
    private Object getPrincipalFromClassName() {
        Object principal = null;

        try {
            Class cls = Class.forName(type);
            principal = getSubject().getPrincipals().oneByType(cls);
        } catch (ClassNotFoundException e) {
            if (log.isErrorEnabled()) {
                log.error("Unable to find class for name [" + type + "]");
            }
        }
        return principal;
    }


    private String getPrincipalProperty(Object principal, String property) throws JspTagException {
        String strValue = null;

        try {
            BeanInfo bi = Introspector.getBeanInfo(principal.getClass());

            // Loop through the properties to get the string value of the specified property
            boolean foundProperty = false;
            for (PropertyDescriptor pd : bi.getPropertyDescriptors()) {
                if (pd.getName().equals(property)) {
                    Object value = pd.getReadMethod().invoke(principal, (Object[]) null);
                    strValue = String.valueOf(value);
                    foundProperty = true;
                    break;
                }
            }

            if (!foundProperty) {
                final String message = "Property [" + property + "] not found in principal of type [" + principal.getClass().getName() + "]";
                if (log.isErrorEnabled()) {
                    log.error(message);
                }
                throw new JspTagException(message);
            }

        } catch (Exception e) {
            final String message = "Error reading property [" + property + "] from principal of type [" + principal.getClass().getName() + "]";
            if (log.isErrorEnabled()) {
                log.error(message, e);
            }
            throw new JspTagException(message, e);
        }

        return strValue;
    }
}