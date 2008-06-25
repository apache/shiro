/*
 * Copyright 2005-2008 Les Hazlewood
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
package org.jsecurity.web.attr;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.JSecurityException;
import org.jsecurity.util.ClassUtils;
import org.jsecurity.util.Initializable;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.beans.PropertyEditor;

/**
 * Convenient superclass for implementations of the {@link WebAttribute} interface.  This class encapsulates
 * converting values from a String form to Object form and vice versa through the use of a <tt>PropertyEditor</tt>
 * configured using {@link #setEditorClass(Class)}.  Subclasses are expected to implement the
 * {@link #onStoreValue(Object, javax.servlet.ServletRequest, javax.servlet.ServletResponse)} and
 * {@link #onRetrieveValue(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
 * methods that perform the actual storing and retrieving of a String value.  This class also contains convenience
 * methods for retrieving the value of a request parameter to be stored.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public abstract class AbstractWebAttribute<T> implements WebAttribute<T>, Initializable {

    public static final String DEFAULT_NAME = "name";

    protected transient final Log log = LogFactory.getLog(getClass());

    protected String name = DEFAULT_NAME;

    protected boolean checkRequestParams = true;
    protected boolean checkRequestParamsFirst = true;

    protected boolean mutable = true;

    /**
     * Property editor class to use to convert attributes to and from strings.
     */
    private Class<? extends PropertyEditor> editorClass = null;

    public AbstractWebAttribute() {
        this(DEFAULT_NAME, true);
    }

    public AbstractWebAttribute(String name) {
        this(name, true);
    }

    public AbstractWebAttribute(String name, boolean checkRequestParams) {
        setName(name);
        setCheckRequestParams(checkRequestParams);
    }

    public AbstractWebAttribute(String name, Class<? extends PropertyEditor> editorClass) {
        this(name, true, editorClass);
    }

    public AbstractWebAttribute(String name, boolean checkRequestParams, Class<? extends PropertyEditor> editorClass) {
        setName(name);
        setCheckRequestParams(checkRequestParams);
        setEditorClass(editorClass);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isCheckRequestParams() {
        return checkRequestParams;
    }

    public void setCheckRequestParams(boolean checkRequestParams) {
        this.checkRequestParams = checkRequestParams;
    }

    public boolean isCheckRequestParamsFirst() {
        return checkRequestParamsFirst;
    }

    public void setCheckRequestParamsFirst(boolean checkRequestParamsFirst) {
        this.checkRequestParamsFirst = checkRequestParamsFirst;
    }

    public Class<? extends PropertyEditor> getEditorClass() {
        return editorClass;
    }

    /**
     * If set, an instance of this class will be used to convert a the object value to a string value (and vice versa)
     * when reading and populating values in
     * {@link javax.servlet.http.HttpServletRequest HttpServletRequest}s, {@link javax.servlet.http.Cookie Cookie}s or
     * {@link javax.servlet.http.HttpSession HttpSession}s.
     *
     * <p>If not set, the string itself will be used.
     *
     * @param editorClass {@link PropertyEditor PropertyEditor} implementation used to
     *                    convert between string values and sessionId objects.
     */
    public void setEditorClass(Class<? extends PropertyEditor> editorClass) {
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

    public void setMutable(boolean mutable) {
        this.mutable = mutable;
    }

    public void init() {
    }

    @SuppressWarnings({"unchecked"})
    protected T fromStringValue(String stringValue) {
        Class clazz = getEditorClass();
        if (clazz == null) {
            try {
                return (T) stringValue;
            } catch (Exception e) {
                String msg = "If the type is not String, you must specify the 'editorClass' property.";
                throw new JSecurityException(msg, e);
            }
        } else {
            PropertyEditor editor = (PropertyEditor) ClassUtils.newInstance(getEditorClass());
            editor.setAsText(stringValue);
            Object value = editor.getValue();
            try {
                return (T) value;
            } catch (ClassCastException e) {
                String msg = "Returned value from PropertyEditor does not match the specified type.";
                throw new JSecurityException(msg, e);
            }
        }
    }

    protected String toStringValue(T value) {
        Class clazz = getEditorClass();
        if (clazz == null) {

            if (log.isDebugEnabled()) {
                log.debug("No 'editorClass' property set - returning value.toString() as the string value for " +
                        "method argument.");
            }
            return value.toString();
        } else {
            PropertyEditor editor = (PropertyEditor) ClassUtils.newInstance(getEditorClass());
            editor.setValue(value);
            return editor.getAsText();
        }
    }

    protected T getFromRequestParam(ServletRequest request) {
        T value = null;

        String paramName = getName();
        String paramValue = request.getParameter(paramName);
        if (paramValue != null) {
            if (log.isTraceEnabled()) {
                log.trace("Found string value [" + paramValue + "] from HttpServletRequest parameter [" + paramName + "]");
            }
            value = fromStringValue(paramValue);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("No string value found in the HttpServletRequest under parameter named [" + paramName + "]");
            }
        }

        return value;
    }

    public final T retrieveValue(ServletRequest request, ServletResponse response) {
        T value = null;
        if (isCheckRequestParams() && isCheckRequestParamsFirst()) {
            value = getFromRequestParam(request);
        }

        if (value == null) {
            value = onRetrieveValue(request, response);
        }

        if (value == null) {
            if (isCheckRequestParams() && !isCheckRequestParamsFirst()) {
                value = getFromRequestParam(request);
            }
        }

        return value;
    }

    protected abstract T onRetrieveValue(ServletRequest request, ServletResponse response);

    public void storeValue(T value, ServletRequest request, ServletResponse response) {
        if (value == null && isMutable()) {
            removeValue(request, response);
            return;
        }

        if (!isMutable()) {
            Object existing = onRetrieveValue(request, response);
            if (existing != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Found existing value stored under name [" + getName() + "].  Ignoring new " +
                            "storage request - this store is immutable after the value has initially been set.");
                }
            }
            return;
        }

        onStoreValue(value, request, response);
    }

    protected abstract void onStoreValue(T value, ServletRequest request, ServletResponse response);
}
