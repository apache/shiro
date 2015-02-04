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
package org.apache.shiro.config;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.beanutils.PropertyUtils;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.beans.PropertyDescriptor;
import java.util.*;


/**
 * Object builder that uses reflection and Apache Commons BeanUtils to build objects given a
 * map of "property values".  Typically these come from the Shiro INI configuration and are used
 * to construct or modify the SecurityManager, its dependencies, and web-based security filters.
 * <p/>
 * Recognizes {@link Factory} implementations and will call
 * {@link org.apache.shiro.util.Factory#getInstance() getInstance} to satisfy any reference to this bean.
 *
 * @since 0.9
 */
public class ReflectionBuilder {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(ReflectionBuilder.class);

    private static final String OBJECT_REFERENCE_BEGIN_TOKEN = "$";
    private static final String ESCAPED_OBJECT_REFERENCE_BEGIN_TOKEN = "\\$";
    private static final String GLOBAL_PROPERTY_PREFIX = "shiro";
    private static final char MAP_KEY_VALUE_DELIMITER = ':';
    private static final String HEX_BEGIN_TOKEN = "0x";
    private static final String NULL_VALUE_TOKEN = "null";
    private static final String EMPTY_STRING_VALUE_TOKEN = "\"\"";
    private static final char STRING_VALUE_DELIMETER = '"';
    private static final char MAP_PROPERTY_BEGIN_TOKEN = '[';
    private static final char MAP_PROPERTY_END_TOKEN = ']';

    private Map<String, ?> objects;

    public ReflectionBuilder() {
        this.objects = new LinkedHashMap<String, Object>();
    }

    public ReflectionBuilder(Map<String, ?> defaults) {
        this.objects = CollectionUtils.isEmpty(defaults) ? new LinkedHashMap<String, Object>() : defaults;
    }

    public Map<String, ?> getObjects() {
        return objects;
    }

    public void setObjects(Map<String, ?> objects) {
        this.objects = CollectionUtils.isEmpty(objects) ? new LinkedHashMap<String, Object>() : objects;
    }

    public Object getBean(String id) {
        return objects.get(id);
    }

    @SuppressWarnings({"unchecked"})
    public <T> T getBean(String id, Class<T> requiredType) {
        if (requiredType == null) {
            throw new NullPointerException("requiredType argument cannot be null.");
        }
        Object bean = getBean(id);
        if (bean == null) {
            return null;
        }
        if (!requiredType.isAssignableFrom(bean.getClass())) {
            throw new IllegalStateException("Bean with id [" + id + "] is not of the required type [" +
                    requiredType.getName() + "].");
        }
        return (T) bean;
    }

    @SuppressWarnings({"unchecked"})
    public Map<String, ?> buildObjects(Map<String, String> kvPairs) {
        if (kvPairs != null && !kvPairs.isEmpty()) {

            // Separate key value pairs into object declarations and property assignment
            // so that all objects can be created up front

            //https://issues.apache.org/jira/browse/SHIRO-85 - need to use LinkedHashMaps here:
            Map<String, String> instanceMap = new LinkedHashMap<String, String>();
            Map<String, String> propertyMap = new LinkedHashMap<String, String>();

            for (Map.Entry<String, String> entry : kvPairs.entrySet()) {
                if (entry.getKey().indexOf('.') < 0 || entry.getKey().endsWith(".class")) {
                    instanceMap.put(entry.getKey(), entry.getValue());
                } else {
                    propertyMap.put(entry.getKey(), entry.getValue());
                }
            }

            // Create all instances
            for (Map.Entry<String, String> entry : instanceMap.entrySet()) {
                createNewInstance((Map<String, Object>) objects, entry.getKey(), entry.getValue());
            }

            // Set all properties
            for (Map.Entry<String, String> entry : propertyMap.entrySet()) {
                applyProperty(entry.getKey(), entry.getValue(), objects);
            }
        }

        //SHIRO-413: init method must be called for constructed objects that are Initializable
        LifecycleUtils.init(objects.values());

        return objects;
    }

    protected void createNewInstance(Map<String, Object> objects, String name, String value) {

        Object currentInstance = objects.get(name);
        if (currentInstance != null) {
            log.info("An instance with name '{}' already exists.  " +
                    "Redefining this object as a new instance of type {}", name, value);
        }

        Object instance;//name with no property, assume right hand side of equals sign is the class name:
        try {
            instance = ClassUtils.newInstance(value);
            if (instance instanceof Nameable) {
                ((Nameable) instance).setName(name);
            }
        } catch (Exception e) {
            String msg = "Unable to instantiate class [" + value + "] for object named '" + name + "'.  " +
                    "Please ensure you've specified the fully qualified class name correctly.";
            throw new ConfigurationException(msg, e);
        }
        objects.put(name, instance);
    }

    protected void applyProperty(String key, String value, Map objects) {

        int index = key.indexOf('.');

        if (index >= 0) {
            String name = key.substring(0, index);
            String property = key.substring(index + 1, key.length());

            if (GLOBAL_PROPERTY_PREFIX.equalsIgnoreCase(name)) {
                applyGlobalProperty(objects, property, value);
            } else {
                applySingleProperty(objects, name, property, value);
            }

        } else {
            throw new IllegalArgumentException("All property keys must contain a '.' character. " +
                    "(e.g. myBean.property = value)  These should already be separated out by buildObjects().");
        }
    }

    protected void applyGlobalProperty(Map objects, String property, String value) {
        for (Object instance : objects.values()) {
            try {
                PropertyDescriptor pd = PropertyUtils.getPropertyDescriptor(instance, property);
                if (pd != null) {
                    applyProperty(instance, property, value);
                }
            } catch (Exception e) {
                String msg = "Error retrieving property descriptor for instance " +
                        "of type [" + instance.getClass().getName() + "] " +
                        "while setting property [" + property + "]";
                throw new ConfigurationException(msg, e);
            }
        }
    }

    protected void applySingleProperty(Map objects, String name, String property, String value) {
        Object instance = objects.get(name);
        if (property.equals("class")) {
            throw new IllegalArgumentException("Property keys should not contain 'class' properties since these " +
                    "should already be separated out by buildObjects().");

        } else if (instance == null) {
            String msg = "Configuration error.  Specified object [" + name + "] with property [" +
                    property + "] without first defining that object's class.  Please first " +
                    "specify the class property first, e.g. myObject = fully_qualified_class_name " +
                    "and then define additional properties.";
            throw new IllegalArgumentException(msg);

        } else {
            applyProperty(instance, property, value);
        }
    }

    protected boolean isReference(String value) {
        return value != null && value.startsWith(OBJECT_REFERENCE_BEGIN_TOKEN);
    }

    protected String getId(String referenceToken) {
        return referenceToken.substring(OBJECT_REFERENCE_BEGIN_TOKEN.length());
    }

    protected Object getReferencedObject(String id) {
        Object o = objects != null && !objects.isEmpty() ? objects.get(id) : null;
        if (o == null) {
            String msg = "The object with id [" + id + "] has not yet been defined and therefore cannot be " +
                    "referenced.  Please ensure objects are defined in the order in which they should be " +
                    "created and made available for future reference.";
            throw new UnresolveableReferenceException(msg);
        }
        return o;
    }

    protected String unescapeIfNecessary(String value) {
        if (value != null && value.startsWith(ESCAPED_OBJECT_REFERENCE_BEGIN_TOKEN)) {
            return value.substring(ESCAPED_OBJECT_REFERENCE_BEGIN_TOKEN.length() - 1);
        }
        return value;
    }

    protected Object resolveReference(String reference) {
        String id = getId(reference);
        log.debug("Encountered object reference '{}'.  Looking up object with id '{}'", reference, id);
        final Object referencedObject = getReferencedObject(id);
        if (referencedObject instanceof Factory) {
            return ((Factory) referencedObject).getInstance();
        }
        return referencedObject;
    }

    protected boolean isTypedProperty(Object object, String propertyName, Class clazz) {
        if (clazz == null) {
            throw new NullPointerException("type (class) argument cannot be null.");
        }
        try {
            PropertyDescriptor descriptor = PropertyUtils.getPropertyDescriptor(object, propertyName);
            if (descriptor == null) {
                String msg = "Property '" + propertyName + "' does not exist for object of " +
                        "type " + object.getClass().getName() + ".";
                throw new ConfigurationException(msg);
            }
            Class propertyClazz = descriptor.getPropertyType();
            return clazz.isAssignableFrom(propertyClazz);
        } catch (ConfigurationException ce) {
            //let it propagate:
            throw ce;
        } catch (Exception e) {
            String msg = "Unable to determine if property [" + propertyName + "] represents a " + clazz.getName();
            throw new ConfigurationException(msg, e);
        }
    }

    protected Set<?> toSet(String sValue) {
        String[] tokens = StringUtils.split(sValue);
        if (tokens == null || tokens.length <= 0) {
            return null;
        }

        //SHIRO-423: check to see if the value is a referenced Set already, and if so, return it immediately:
        if (tokens.length == 1 && isReference(tokens[0])) {
            Object reference = resolveReference(tokens[0]);
            if (reference instanceof Set) {
                return (Set)reference;
            }
        }

        Set<String> setTokens = new LinkedHashSet<String>(Arrays.asList(tokens));

        //now convert into correct values and/or references:
        Set<Object> values = new LinkedHashSet<Object>(setTokens.size());
        for (String token : setTokens) {
            Object value = resolveValue(token);
            values.add(value);
        }
        return values;
    }

    protected Map<?, ?> toMap(String sValue) {
        String[] tokens = StringUtils.split(sValue, StringUtils.DEFAULT_DELIMITER_CHAR,
                StringUtils.DEFAULT_QUOTE_CHAR, StringUtils.DEFAULT_QUOTE_CHAR, true, true);
        if (tokens == null || tokens.length <= 0) {
            return null;
        }

        //SHIRO-423: check to see if the value is a referenced Map already, and if so, return it immediately:
        if (tokens.length == 1 && isReference(tokens[0])) {
            Object reference = resolveReference(tokens[0]);
            if (reference instanceof Map) {
                return (Map)reference;
            }
        }

        Map<String, String> mapTokens = new LinkedHashMap<String, String>(tokens.length);
        for (String token : tokens) {
            String[] kvPair = StringUtils.split(token, MAP_KEY_VALUE_DELIMITER);
            if (kvPair == null || kvPair.length != 2) {
                String msg = "Map property value [" + sValue + "] contained key-value pair token [" +
                        token + "] that does not properly split to a single key and pair.  This must be the " +
                        "case for all map entries.";
                throw new ConfigurationException(msg);
            }
            mapTokens.put(kvPair[0], kvPair[1]);
        }

        //now convert into correct values and/or references:
        Map<Object, Object> map = new LinkedHashMap<Object, Object>(mapTokens.size());
        for (Map.Entry<String, String> entry : mapTokens.entrySet()) {
            Object key = resolveValue(entry.getKey());
            Object value = resolveValue(entry.getValue());
            map.put(key, value);
        }
        return map;
    }

    // @since 1.2.2
    // TODO: make protected in 1.3+
    private Collection<?> toCollection(String sValue) {

        String[] tokens = StringUtils.split(sValue);
        if (tokens == null || tokens.length <= 0) {
            return null;
        }

        //SHIRO-423: check to see if the value is a referenced Collection already, and if so, return it immediately:
        if (tokens.length == 1 && isReference(tokens[0])) {
            Object reference = resolveReference(tokens[0]);
            if (reference instanceof Collection) {
                return (Collection)reference;
            }
        }

        //now convert into correct values and/or references:
        List<Object> values = new ArrayList<Object>(tokens.length);
        for (String token : tokens) {
            Object value = resolveValue(token);
            values.add(value);
        }
        return values;
    }

    protected List<?> toList(String sValue) {
        String[] tokens = StringUtils.split(sValue);
        if (tokens == null || tokens.length <= 0) {
            return null;
        }

        //SHIRO-423: check to see if the value is a referenced List already, and if so, return it immediately:
        if (tokens.length == 1 && isReference(tokens[0])) {
            Object reference = resolveReference(tokens[0]);
            if (reference instanceof List) {
                return (List)reference;
            }
        }

        //now convert into correct values and/or references:
        List<Object> values = new ArrayList<Object>(tokens.length);
        for (String token : tokens) {
            Object value = resolveValue(token);
            values.add(value);
        }
        return values;
    }

    protected byte[] toBytes(String sValue) {
        if (sValue == null) {
            return null;
        }
        byte[] bytes;
        if (sValue.startsWith(HEX_BEGIN_TOKEN)) {
            String hex = sValue.substring(HEX_BEGIN_TOKEN.length());
            bytes = Hex.decode(hex);
        } else {
            //assume base64 encoded:
            bytes = Base64.decode(sValue);
        }
        return bytes;
    }

    protected Object resolveValue(String stringValue) {
        Object value;
        if (isReference(stringValue)) {
            value = resolveReference(stringValue);
        } else {
            value = unescapeIfNecessary(stringValue);
        }
        return value;
    }

    protected String checkForNullOrEmptyLiteral(String stringValue) {
        if (stringValue == null) {
            return null;
        }
        //check if the value is the actual literal string 'null' (expected to be wrapped in quotes):
        if (stringValue.equals("\"null\"")) {
            return NULL_VALUE_TOKEN;
        }
        //or the actual literal string of two quotes '""' (expected to be wrapped in quotes):
        else if (stringValue.equals("\"\"\"\"")) {
            return EMPTY_STRING_VALUE_TOKEN;
        } else {
            return stringValue;
        }
    }
    
    protected void applyProperty(Object object, String propertyPath, Object value) {

        int mapBegin = propertyPath.indexOf(MAP_PROPERTY_BEGIN_TOKEN);
        int mapEnd = -1;
        String mapPropertyPath = null;
        String keyString = null;

        String remaining = null;
        
        if (mapBegin >= 0) {
            //a map is being referenced in the overall property path.  Find just the map's path:
            mapPropertyPath = propertyPath.substring(0, mapBegin);
            //find the end of the map reference:
            mapEnd = propertyPath.indexOf(MAP_PROPERTY_END_TOKEN, mapBegin);
            //find the token in between the [ and the ] (the map/array key or index):
            keyString = propertyPath.substring(mapBegin+1, mapEnd);

            //find out if there is more path reference to follow.  If not, we're at a terminal of the OGNL expression
            if (propertyPath.length() > (mapEnd+1)) {
                remaining = propertyPath.substring(mapEnd+1);
                if (remaining.startsWith(".")) {
                    remaining = StringUtils.clean(remaining.substring(1));
                }
            }
        }
        
        if (remaining == null) {
            //we've terminated the OGNL expression.  Check to see if we're assigning a property or a map entry:
            if (keyString == null) {
                //not a map or array value assignment - assign the property directly:
                setProperty(object, propertyPath, value);
            } else {
                //we're assigning a map or array entry.  Check to see which we should call:
                if (isTypedProperty(object, mapPropertyPath, Map.class)) {
                    Map map = (Map)getProperty(object, mapPropertyPath);
                    Object mapKey = resolveValue(keyString);
                    //noinspection unchecked
                    map.put(mapKey, value);
                } else {
                    //must be an array property.  Convert the key string to an index:
                    int index = Integer.valueOf(keyString);
                    setIndexedProperty(object, mapPropertyPath, index, value);
                }
            }
        } else {
            //property is being referenced as part of a nested path.  Find the referenced map/array entry and
            //recursively call this method with the remaining property path
            Object referencedValue = null;
            if (isTypedProperty(object, mapPropertyPath, Map.class)) {
                Map map = (Map)getProperty(object, mapPropertyPath);
                Object mapKey = resolveValue(keyString);
                referencedValue = map.get(mapKey);
            } else {
                //must be an array property:
                int index = Integer.valueOf(keyString);
                referencedValue = getIndexedProperty(object, mapPropertyPath, index);
            }

            if (referencedValue == null) {
                throw new ConfigurationException("Referenced map/array value '" + mapPropertyPath + "[" +
                keyString + "]' does not exist.");
            }

            applyProperty(referencedValue, remaining, value);
        }
    }
    
    private void setProperty(Object object, String propertyPath, Object value) {
        try {
            if (log.isTraceEnabled()) {
                log.trace("Applying property [{}] value [{}] on object of type [{}]",
                        new Object[]{propertyPath, value, object.getClass().getName()});
            }
            BeanUtils.setProperty(object, propertyPath, value);
        } catch (Exception e) {
            String msg = "Unable to set property '" + propertyPath + "' with value [" + value + "] on object " +
                    "of type " + (object != null ? object.getClass().getName() : null) + ".  If " +
                    "'" + value + "' is a reference to another (previously defined) object, prefix it with " +
                    "'" + OBJECT_REFERENCE_BEGIN_TOKEN + "' to indicate that the referenced " +
                    "object should be used as the actual value.  " +
                    "For example, " + OBJECT_REFERENCE_BEGIN_TOKEN + value;
            throw new ConfigurationException(msg, e);
        }
    }
    
    private Object getProperty(Object object, String propertyPath) {
        try {
            return PropertyUtils.getProperty(object, propertyPath);
        } catch (Exception e) {
            throw new ConfigurationException("Unable to access property '" + propertyPath + "'", e);
        }
    }
    
    private void setIndexedProperty(Object object, String propertyPath, int index, Object value) {
        try {
            PropertyUtils.setIndexedProperty(object, propertyPath, index, value);
        } catch (Exception e) {
            throw new ConfigurationException("Unable to set array property '" + propertyPath + "'", e);
        }
    }
    
    private Object getIndexedProperty(Object object, String propertyPath, int index) {
        try {
            return PropertyUtils.getIndexedProperty(object, propertyPath, index);
        } catch (Exception e) {
            throw new ConfigurationException("Unable to acquire array property '" + propertyPath + "'", e);
        }
    }
    
    protected boolean isIndexedPropertyAssignment(String propertyPath) {
        return propertyPath.endsWith("" + MAP_PROPERTY_END_TOKEN);
    }

    protected void applyProperty(Object object, String propertyName, String stringValue) {

        Object value;

        if (NULL_VALUE_TOKEN.equals(stringValue)) {
            value = null;
        } else if (EMPTY_STRING_VALUE_TOKEN.equals(stringValue)) {
            value = StringUtils.EMPTY_STRING;
        } else if (isIndexedPropertyAssignment(propertyName)) {
            String checked = checkForNullOrEmptyLiteral(stringValue);
            value = resolveValue(checked);
        } else if (isTypedProperty(object, propertyName, Set.class)) {
            value = toSet(stringValue);
        } else if (isTypedProperty(object, propertyName, Map.class)) {
            value = toMap(stringValue);
        } else if (isTypedProperty(object, propertyName, List.class)) {
            value = toList(stringValue);
        } else if (isTypedProperty(object, propertyName, Collection.class)) {
            value = toCollection(stringValue);
        } else if (isTypedProperty(object, propertyName, byte[].class)) {
            value = toBytes(stringValue);
        } else if (isTypedProperty(object, propertyName, ByteSource.class)) {
            byte[] bytes = toBytes(stringValue);
            value = ByteSource.Util.bytes(bytes);
        } else {
            String checked = checkForNullOrEmptyLiteral(stringValue);
            value = resolveValue(checked);
        }

        applyProperty(object, propertyName, value);
    }

}
