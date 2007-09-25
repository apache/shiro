/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.web.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.JSecurityException;
import org.jsecurity.util.ClassUtils;
import org.jsecurity.util.Initializable;
import org.jsecurity.web.WebStore;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.beans.PropertyEditor;

/**
 * Convenient superclass for implementations of the {@link WebStore} interface.  This class encapsulates
 * converting values from a String form to Object form and vice versa through the use of a <tt>PropertyEditor</tt>
 * configured using {@link #setEditorClass(Class)}.  Subclasses are expected to implement the
 * {@link #onStoreValue(Object, javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)}
 * and {@link #onRetrieveValue(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)}
 * methods that perform the actual storing and retrieving of a String value.  This class also contains convenience
 * methods for retrieving the value of a request parameter to be stored.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class AbstractWebStore<T> extends SecurityWebSupport implements WebStore<T>, Initializable {

    public static final String DEFAULT_NAME = "name";

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected String name = DEFAULT_NAME;

    protected boolean checkRequestParams = true;
    protected boolean checkRequestParamsFirst = true;

    protected boolean mutable = true;

    /**
     * Property editor class to use to convert IDs to and from strings.
     */
    private Class<? extends PropertyEditor> editorClass = null;

    public AbstractWebStore() {
        this( DEFAULT_NAME, true );
    }

    public AbstractWebStore( String name ) {
        this( name, true );
    }

    public AbstractWebStore( String name, boolean checkRequestParams ) {
        setName( name );
        setCheckRequestParams( checkRequestParams );
    }

    public AbstractWebStore( String name, Class<? extends PropertyEditor> editorClass ) {
        this( name, true, editorClass );
    }

    public AbstractWebStore( String name, boolean checkRequestParams, Class<? extends PropertyEditor> editorClass ) {
        setName( name );
        setCheckRequestParams( checkRequestParams );
        setEditorClass( editorClass );
    }

    public String getName() {
        return name;
    }

    public void setName( String name ) {
        this.name = name;
    }

    public boolean isCheckRequestParams() {
        return checkRequestParams;
    }

    public void setCheckRequestParams( boolean checkRequestParams ) {
        this.checkRequestParams = checkRequestParams;
    }

    public boolean isCheckRequestParamsFirst() {
        return checkRequestParamsFirst;
    }

    public void setCheckRequestParamsFirst( boolean checkRequestParamsFirst ) {
        this.checkRequestParamsFirst = checkRequestParamsFirst;
    }

    public Class<? extends PropertyEditor> getEditorClass() {
        return editorClass;
    }

    /**
     * If set, an instance of this class will be used to convert a Session ID to a string value (and vice versa) when
     * reading and populating values in
     * {@link javax.servlet.http.HttpServletRequest HttpServletRequest}s, {@link javax.servlet.http.Cookie Cookie}s or
     * {@link javax.servlet.http.HttpSession HttpSession}s.
     * <p/>
     * <p>If not set, the string itself will be used.
     *
     * @param editorClass {@link PropertyEditor PropertyEditor} implementation used to
     *                    convert between string values and sessionId objects.
     */
    public void setEditorClass( Class<? extends PropertyEditor> editorClass ) {
        this.editorClass = editorClass;
    }

    /**
     * Returns <tt>true</tt> if the value stored can be changed once it has been set, <tt>false</tt> if it cannot.
     * <p>Default is <tt>true</tt>.
     *
     * @return <tt>true</tt> if the value stored can be changed once it has been set, <tt>false</tt> if it cannot.
     */
    public boolean isMutable() {
        return mutable;
    }

    public void setMutable( boolean mutable ) {
        this.mutable = mutable;
    }

    public void init() {
    }

    protected T fromStringValue( String stringValue ) {
        Class clazz = getEditorClass();
        if ( clazz == null ) {
            try {
                return (T)stringValue;
            } catch ( Exception e ) {
                String msg = "If the Generics type is not String, you must specify the 'editorClass' property.";
                throw new JSecurityException( msg, e );
            }
        } else {
            PropertyEditor editor = (PropertyEditor)ClassUtils.newInstance( getEditorClass() );
            editor.setAsText( stringValue );
            Object value = editor.getValue();
            try {
                T retVal = (T)value;
                return retVal;
            } catch ( ClassCastException e ) {
                String msg = "Returned value from PropertyEditor does not match the specified Generics type.";
                throw new JSecurityException( msg, e );
            }
        }
    }

    protected String toStringValue( T value ) {
        Class clazz = getEditorClass();
        if ( clazz == null ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "No 'editorClass' property set - returning value.toString() as the string value for " +
                    "method argument." );
            }
            return value.toString();
        } else {
            PropertyEditor editor = (PropertyEditor)ClassUtils.newInstance( getEditorClass() );
            editor.setValue( value );
            return editor.getAsText();
        }
    }

    protected T getFromRequestParam( HttpServletRequest request ) {
        T value = null;

        String paramName = getName();
        String paramValue = request.getParameter( paramName );
        if ( paramValue != null ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Found string value [" + paramValue + "] from HttpServletRequest parameter [" + paramName + "]" );
            }
            value = fromStringValue( paramValue );
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "No string value found in the HttpServletRequest under parameter named [" + paramName + "]" );
            }
        }

        return value;
    }

    public final T retrieveValue( HttpServletRequest request, HttpServletResponse response ) {
        T value = null;
        if ( isCheckRequestParams() && isCheckRequestParamsFirst() ) {
            value = getFromRequestParam( request );
        }
        
        if ( value == null ) {
            value = onRetrieveValue( request, response );
        }

        if ( value == null ) {
            if ( isCheckRequestParams() && !isCheckRequestParamsFirst() ) {
                value = getFromRequestParam( request ); 
            }
        }

        return value;
    }

    protected abstract T onRetrieveValue( HttpServletRequest request, HttpServletResponse response );

    public void storeValue( T value, HttpServletRequest request, HttpServletResponse response ) {
        if ( value == null ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "Will not store a null value - returning." );
                return;
            }
        }

        if ( !isMutable() ) {
            Object existing = onRetrieveValue( request, response );
            if ( existing != null ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "Found existing value stored under name [" + getName() + "].  Ignoring new " +
                        "storage request - this store is immutable after the value has initially been set." );
                }
            }
            return;
        }

        onStoreValue( value, request, response );
    }

    protected abstract void onStoreValue( T value, HttpServletRequest request, HttpServletResponse response );
}
