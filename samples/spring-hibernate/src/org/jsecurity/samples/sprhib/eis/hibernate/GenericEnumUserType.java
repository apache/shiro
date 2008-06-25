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
package org.jsecurity.samples.sprhib.eis.hibernate;

import org.hibernate.HibernateException;
import org.hibernate.type.NullableType;
import org.hibernate.type.TypeFactory;
import org.hibernate.usertype.EnhancedUserType;
import org.hibernate.usertype.ParameterizedType;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

/**
 * Implements a generic enum user type identified / represented by a single identifier / column.
 *
 *
 * <ul> <li>The enum type being represented by the certain user type must be set by using the
 * 'enumClass' property.</li> <li>The identifier representing a enum value is retrieved by the
 * identifierMethod. The name of the identifier method can be specified by the 'identifierMethod'
 * property and by default the name() method is used.</li> <li>The identifier type is automatically
 * determined by the return-type of the identifierMethod.</li> <li>The valueOfMethod is the name of
 * the static factory method returning the enumeration object being represented by the given
 * indentifier. The valueOfMethod's name can be specified by setting the 'valueOfMethod' property.
 * The default valueOfMethod's name is 'valueOf'.</li> </ul> </p> <p>Example of an enum type
 * represented by an int value:
 * <code><pre>public enum SimpleNumber {
 *     Unknown(-1), Zero(0), One(1), Two(2), Three(3);
 * <p/>
 *     public int toInt() { return value; }
 * <p/>
 *     public SimpleNumber fromInt(int value) {
 *         switch(value) {
 *             case 0: return Zero;
 *             case 1: return One;
 *             case 2: return Two;
 *             case 3: return Three;
 *             default: return Unknown;
 *         }
 *     }
 * }</pre></code>
 *
 * <p>The Mapping would look like this:
 * <code><pre>&lt;typedef name=&quot;SimpleNumber&quot; class=&quot;GenericEnumUserType&quot;&gt;
 * &lt;param name="enumClass">SimpleNumber&lt;/param&gt;
 * &lt;param name="identifierMethod">toInt&lt;/param&gt;
 * &lt;param name="valueOfMethod">fromInt&lt;/param&gt;
 * &lt;/typedef&gt;
 * &lt;class ...&gt;
 * ...
 * &lt;property name="number" column="number" type="SimpleNumber"/&gt;
 * &lt;/class&gt;
 * </pre></code>
 *
 * @author Martin Kersten
 * @author Les Hazlewood
 * @since 05.05.2005
 */
@SuppressWarnings(value = "unchecked")
public class GenericEnumUserType implements EnhancedUserType, ParameterizedType {

    private Class<? extends Enum> enumClass;

    private Method identifierMethod;
    private Method valueOfMethod;

    private static final String defaultIdentifierMethodName = "name";
    private static final String defaultValueOfMethodName = "valueOf";

    private static final Class[] NULL_CLASS_VARARG = null;
    private static final Object[] NULL_OBJECT_VARARG = null;
    private static final char SINGLE_QUOTE = '\'';

    private NullableType type;
    private int[] sqlTypes;

    public void setParameterValues(Properties parameters) {
        String enumClassName = parameters.getProperty("enumClass");
        try {
            enumClass = Class.forName(enumClassName).asSubclass(Enum.class);
        }
        catch (ClassNotFoundException exception) {
            throw new HibernateException("Enum class not found", exception);
        }

        String identifierMethodName =
                parameters.getProperty("identifierMethod", defaultIdentifierMethodName);

        Class<?> identifierType;
        try {
            identifierMethod = enumClass.getMethod(identifierMethodName, NULL_CLASS_VARARG);
            identifierType = identifierMethod.getReturnType();
        }
        catch (Exception exception) {
            throw new HibernateException("Failed to obtain identifier method", exception);
        }

        type = (NullableType) TypeFactory.basic(identifierType.getName());

        if (type == null) {
            throw new HibernateException("Unsupported identifier type " + identifierType.getName());
        }

        sqlTypes = new int[]{type.sqlType()};

        String valueOfMethodName =
                parameters.getProperty("valueOfMethod", defaultValueOfMethodName);

        try {
            valueOfMethod = enumClass.getMethod(valueOfMethodName, identifierType);
        }
        catch (Exception exception) {
            throw new HibernateException("Failed to obtain valueOf method", exception);
        }
    }

    public Class returnedClass() {
        return enumClass;
    }

    public Object nullSafeGet(ResultSet rs, String[] names, Object owner)
            throws HibernateException, SQLException {
        Object identifier = type.get(rs, names[0]);
        if (identifier == null || rs.wasNull()) {
            return null;
        }
        try {
            return valueOfMethod.invoke(enumClass, identifier);
        } catch (Exception exception) {
            String msg = "Exception while invoking valueOfMethod [" + valueOfMethod.getName() +
                    "] of Enum class [" + enumClass.getName() + "] with argument of type [" +
                    identifier.getClass().getName() + "], value=[" + identifier + "]";
            throw new HibernateException(msg, exception);
        }
    }

    public void nullSafeSet(PreparedStatement st, Object value, int index)
            throws HibernateException, SQLException {
        if (value == null) {
            st.setNull(index, sqlTypes[0]);
        } else {
            try {
                Object identifier = identifierMethod.invoke(value, NULL_OBJECT_VARARG);
                type.set(st, identifier, index);
            } catch (Exception exception) {
                String msg = "Exception while invoking identifierMethod [" + identifierMethod.getName() +
                        "] of Enum class [" + enumClass.getName() +
                        "] with argument of type [" + value.getClass().getName() + "], value=[" + value + "]";
                throw new HibernateException(msg, exception);
            }
        }
    }

    public int[] sqlTypes() {
        return sqlTypes;
    }

    public Object assemble(Serializable cached, Object owner) throws HibernateException {
        return cached;
    }

    public Object deepCopy(Object value) throws HibernateException {
        return value;
    }

    public Serializable disassemble(Object value) throws HibernateException {
        return (Serializable) value;
    }

    public String objectToSQLString(Object value) {
        return SINGLE_QUOTE + ((Enum) value).name() + SINGLE_QUOTE;
    }

    public String toXMLString(Object value) {
        return ((Enum) value).name();
    }

    public Object fromXMLString(String xmlValue) {
        return Enum.valueOf(enumClass, xmlValue);
    }

    public boolean equals(Object x, Object y) throws HibernateException {
        return x == y;
    }

    public int hashCode(Object x) throws HibernateException {
        return x.hashCode();
    }

    public boolean isMutable() {
        return false;
    }

    public Object replace(Object original, Object target, Object owner)
            throws HibernateException {
        return original;
    }
}



