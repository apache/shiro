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
package org.apache.shiro.config.ogdl;

import java.beans.PropertyDescriptor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.beanutils.BeanUtilsBean;
import org.apache.commons.beanutils.ConvertUtilsBean;
import org.apache.commons.beanutils.SuppressPropertiesBeanIntrospector;
import org.apache.shiro.lang.codec.Base64;
import org.apache.shiro.lang.codec.Hex;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.ogdl.event.BeanEvent;
import org.apache.shiro.config.ogdl.event.ConfiguredBeanEvent;
import org.apache.shiro.config.ogdl.event.DestroyedBeanEvent;
import org.apache.shiro.config.ogdl.event.InitializedBeanEvent;
import org.apache.shiro.config.ogdl.event.InstantiatedBeanEvent;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.EventBusAware;
import org.apache.shiro.event.Subscribe;
import org.apache.shiro.event.support.DefaultEventBus;
import org.apache.shiro.lang.util.Assert;
import org.apache.shiro.lang.util.ByteSource;
import org.apache.shiro.lang.util.ClassUtils;
import org.apache.shiro.lang.util.Factory;
import org.apache.shiro.lang.util.LifecycleUtils;
import org.apache.shiro.lang.util.Nameable;
import org.apache.shiro.lang.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Object builder that uses reflection and Apache Commons BeanUtils to build objects given a
 * map of "property values".  Typically these come from the Shiro INI configuration and are used
 * to construct or modify the SecurityManager, its dependencies, and web-based security filters.
 * <p/>
 * Recognizes {@link Factory} implementations and will call
 * {@link org.apache.shiro.lang.util.Factory#getInstance() getInstance} to satisfy any reference to this bean.
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

    private static final String EVENT_BUS_NAME = "eventBus";

    private final Map<String, Object> objects;

    /**
     * Interpolation allows for ${key} substitution of values.
     * @since 1.4
     */
    private Interpolator interpolator;

    /**
     * @since 1.3
     */
    private EventBus eventBus;
    /**
     * Keeps track of event subscribers that were automatically registered by this ReflectionBuilder during
     * object construction.  This is used in case a new EventBus is discovered during object graph
     * construction:  upon discovery of the new EventBus, the existing subscribers will be unregistered from the
     * old EventBus and then re-registered with the new EventBus.
     *
     * @since 1.3
     */
    private final Map<String,Object> registeredEventSubscribers;

    /**
     * @since 1.4
     */
    private final BeanUtilsBean beanUtilsBean;

    //@since 1.3
    private Map<String,Object> createDefaultObjectMap() {
        Map<String,Object> map = new LinkedHashMap<String, Object>();
        map.put(EVENT_BUS_NAME, new DefaultEventBus());
        return map;
    }

    public ReflectionBuilder() {
        this(null);
    }

    public ReflectionBuilder(Map<String, ?> defaults) {

        // SHIRO-619
        // SHIRO-739
        beanUtilsBean = new BeanUtilsBean(new ConvertUtilsBean() {
            @Override
            public Object convert(String value, Class clazz) {
                if (clazz.isEnum()){
                    return Enum.valueOf(clazz, value);
                }else{
                    return super.convert(value, clazz);
                }
            }
        });
        beanUtilsBean.getPropertyUtils().addBeanIntrospector(SuppressPropertiesBeanIntrospector.SUPPRESS_CLASS);

        this.interpolator = createInterpolator();

        this.objects = createDefaultObjectMap();
        this.registeredEventSubscribers = new LinkedHashMap<String,Object>();
        apply(defaults);
    }

    private void apply(Map<String, ?> objects) {
        if(!isEmpty(objects)) {
            this.objects.putAll(objects);
        }
        EventBus found = findEventBus(this.objects);
        Assert.notNull(found, "An " + EventBus.class.getName() + " instance must be present in the object defaults");
        enableEvents(found);
    }

    public Map<String, ?> getObjects() {
        return objects;
    }

    /**
     * @param objects
     */
    public void setObjects(Map<String, ?> objects) {
        this.objects.clear();
        this.objects.putAll(createDefaultObjectMap());
        apply(objects);
    }

    //@since 1.3
    private void enableEvents(EventBus eventBus) {
        Assert.notNull(eventBus, "EventBus argument cannot be null.");
        //clean up old auto-registered subscribers:
        for (Object subscriber : this.registeredEventSubscribers.values()) {
            this.eventBus.unregister(subscriber);
        }
        this.registeredEventSubscribers.clear();

        this.eventBus = eventBus;

        for(Map.Entry<String,Object> entry : this.objects.entrySet()) {
            enableEventsIfNecessary(entry.getValue(), entry.getKey());
        }
    }

    //@since 1.3
    private void enableEventsIfNecessary(Object bean, String name) {
        boolean applied = applyEventBusIfNecessary(bean);
        if (!applied) {
            //if the event bus is applied, and the bean wishes to be a subscriber as well (not just a publisher),
            // we assume that the implementation registers itself with the event bus, i.e. eventBus.register(this);

            //if the event bus isn't applied, only then do we need to check to see if the bean is an event subscriber,
            // and if so, register it on the event bus automatically since it has no ability to do so itself:
            if (isEventSubscriber(bean, name)) {
                //found an event subscriber, so register them with the EventBus:
                this.eventBus.register(bean);
                this.registeredEventSubscribers.put(name, bean);
            }
        }
    }

    //@since 1.3
    private boolean isEventSubscriber(Object bean, String name) {
        List annotatedMethods = ClassUtils.getAnnotatedMethods(bean.getClass(), Subscribe.class);
        return !isEmpty(annotatedMethods);
    }

    //@since 1.3
    protected EventBus findEventBus(Map<String,?> objects) {

        if (isEmpty(objects)) {
            return null;
        }

        //prefer a named object first:
        Object value = objects.get(EVENT_BUS_NAME);
        if (value != null && value instanceof EventBus) {
            return (EventBus)value;
        }

        //couldn't find a named 'eventBus' EventBus object.  Try to find the first typed value we can:
        for( Object v : objects.values()) {
            if (v instanceof EventBus) {
                return (EventBus)v;
            }
        }

        return null;
    }

    private boolean applyEventBusIfNecessary(Object value) {
        if (value instanceof EventBusAware) {
            ((EventBusAware)value).setEventBus(this.eventBus);
            return true;
        }
        return false;
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
        Assert.state(requiredType.isAssignableFrom(bean.getClass()),
                "Bean with id [" + id + "] is not of the required type [" + requiredType.getName() + "].");
        return (T) bean;
    }

    private String parseBeanId(String lhs) {
        Assert.notNull(lhs);
        if (lhs.indexOf('.') < 0) {
            return lhs;
        }
        String classSuffix = ".class";
        int index = lhs.indexOf(classSuffix);
        if (index >= 0) {
            return lhs.substring(0, index);
        }
        return null;
    }

    @SuppressWarnings({"unchecked"})
    public Map<String, ?> buildObjects(Map<String, String> kvPairs) {

        if (kvPairs != null && !kvPairs.isEmpty()) {

            BeanConfigurationProcessor processor = new BeanConfigurationProcessor();

            for (Map.Entry<String, String> entry : kvPairs.entrySet()) {
                String lhs = entry.getKey();
                String rhs = interpolator.interpolate(entry.getValue());

                String beanId = parseBeanId(lhs);
                if (beanId != null) { //a beanId could be parsed, so the line is a bean instance definition
                    processor.add(new InstantiationStatement(beanId, rhs));
                } else { //the line must be a property configuration
                    processor.add(new AssignmentStatement(lhs, rhs));
                }
            }

            processor.execute();

            //SHIRO-778: onInit method on AuthenticatingRealm is called twice
            objects.keySet().stream()
                    .filter(key -> !kvPairs.containsKey(key))
                    .forEach(key -> LifecycleUtils.init(objects.get(key)));
        } else {
            //SHIRO-413: init method must be called for constructed objects that are Initializable
            LifecycleUtils.init(objects.values());
        }

        return objects;
    }

    public void destroy() {
        final Map<String, Object> immutableObjects = Collections.unmodifiableMap(objects);

        //destroy objects in the opposite order they were initialized:
        List<Map.Entry<String,?>> entries = new ArrayList<Map.Entry<String,?>>(objects.entrySet());
        Collections.reverse(entries);

        for(Map.Entry<String, ?> entry: entries) {
            String id = entry.getKey();
            Object bean = entry.getValue();

            //don't destroy the eventbus until the end - we need it to still be 'alive' while publishing destroy events:
            if (bean != this.eventBus) { //memory equality check (not .equals) on purpose
                LifecycleUtils.destroy(bean);
                BeanEvent event = new DestroyedBeanEvent(id, bean, immutableObjects);
                eventBus.publish(event);
                this.eventBus.unregister(bean); //bean is now destroyed - it should not receive any other events
            }
        }
        //only now destroy the event bus:
        LifecycleUtils.destroy(this.eventBus);
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
                PropertyDescriptor pd = beanUtilsBean.getPropertyUtils().getPropertyDescriptor(instance, property);
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
            PropertyDescriptor descriptor = beanUtilsBean.getPropertyUtils().getPropertyDescriptor(object, propertyName);
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
    protected Collection<?> toCollection(String sValue) {

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
            beanUtilsBean.setProperty(object, propertyPath, value);
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
            return beanUtilsBean.getPropertyUtils().getProperty(object, propertyPath);
        } catch (Exception e) {
            throw new ConfigurationException("Unable to access property '" + propertyPath + "'", e);
        }
    }
    
    private void setIndexedProperty(Object object, String propertyPath, int index, Object value) {
        try {
            beanUtilsBean.getPropertyUtils().setIndexedProperty(object, propertyPath, index, value);
        } catch (Exception e) {
            throw new ConfigurationException("Unable to set array property '" + propertyPath + "'", e);
        }
    }
    
    private Object getIndexedProperty(Object object, String propertyPath, int index) {
        try {
            return beanUtilsBean.getPropertyUtils().getIndexedProperty(object, propertyPath, index);
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

    private Interpolator createInterpolator() {

        if (ClassUtils.isAvailable("org.apache.commons.configuration2.interpol.ConfigurationInterpolator")) {
            return new CommonsInterpolator();
        }

        return new DefaultInterpolator();
    }

    /**
     * Sets the {@link Interpolator} used when evaluating the right side of the expressions.
     * @since 1.4
     */
    public void setInterpolator(Interpolator interpolator) {
        this.interpolator = interpolator;
    }

    private class BeanConfigurationProcessor {

        private final List<Statement> statements = new ArrayList<Statement>();
        private final List<BeanConfiguration> beanConfigurations = new ArrayList<BeanConfiguration>();

        public void add(Statement statement) {

            statements.add(statement); //we execute bean configuration statements in the order they are declared.

            if (statement instanceof InstantiationStatement) {
                InstantiationStatement is = (InstantiationStatement)statement;
                beanConfigurations.add(new BeanConfiguration(is));
            } else {
                AssignmentStatement as = (AssignmentStatement)statement;
                //statements always apply to the most recently defined bean configuration with the same name, so we
                //have to traverse the configuration list starting at the end (most recent elements are appended):
                boolean addedToConfig = false;
                String beanName = as.getRootBeanName();
                for( int i = beanConfigurations.size()-1; i >= 0; i--) {
                    BeanConfiguration mostRecent = beanConfigurations.get(i);
                    String mostRecentBeanName = mostRecent.getBeanName();
                    if (beanName.equals(mostRecentBeanName)) {
                        mostRecent.add(as);
                        addedToConfig = true;
                        break;
                    }
                }

                if (!addedToConfig) {
                    // the AssignmentStatement must be for an existing bean that does not yet have a corresponding
                    // configuration object (this would happen if the bean is in the default objects map). Because
                    // BeanConfiguration instances don't exist for default (already instantiated) beans,
                    // we simulate a creation of one to satisfy this processors implementation:
                    beanConfigurations.add(new BeanConfiguration(as));
                }
            }
        }

        public void execute() {

            for( Statement statement : statements) {

                statement.execute();

                BeanConfiguration bd = statement.getBeanConfiguration();

                if (bd.isExecuted()) { //bean is fully configured, no more statements to execute for it:

                    //bean configured overrides the 'eventBus' bean - replace the existing eventBus with the one configured:
                    if (bd.getBeanName().equals(EVENT_BUS_NAME)) {
                        EventBus eventBus = (EventBus)bd.getBean();
                        enableEvents(eventBus);
                    }

                    //ignore global 'shiro.' shortcut mechanism:
                    if (!bd.isGlobalConfig()) {
                        BeanEvent event = new ConfiguredBeanEvent(bd.getBeanName(), bd.getBean(),
                                Collections.unmodifiableMap(objects));
                        eventBus.publish(event);
                    }

                    //initialize the bean if necessary:
                    LifecycleUtils.init(bd.getBean());

                    //ignore global 'shiro.' shortcut mechanism:
                    if (!bd.isGlobalConfig()) {
                        BeanEvent event = new InitializedBeanEvent(bd.getBeanName(), bd.getBean(),
                                Collections.unmodifiableMap(objects));
                        eventBus.publish(event);
                    }
                }
            }
        }
    }

    private class BeanConfiguration {

        private final InstantiationStatement instantiationStatement;
        private final List<AssignmentStatement> assignments = new ArrayList<AssignmentStatement>();
        private final String beanName;
        private Object bean;

        private BeanConfiguration(InstantiationStatement statement) {
            statement.setBeanConfiguration(this);
            this.instantiationStatement = statement;
            this.beanName = statement.lhs;
        }

        private BeanConfiguration(AssignmentStatement as) {
            this.instantiationStatement = null;
            this.beanName = as.getRootBeanName();
            add(as);
        }

        public String getBeanName() {
            return this.beanName;
        }

        public boolean isGlobalConfig() { //BeanConfiguration instance representing the global 'shiro.' properties
            // (we should remove this concept).
            return GLOBAL_PROPERTY_PREFIX.equals(getBeanName());
        }

        public void add(AssignmentStatement as) {
            as.setBeanConfiguration(this);
            assignments.add(as);
        }

        /**
         * When this configuration is parsed sufficiently to create (or find) an actual bean instance, that instance
         * will be associated with its configuration by setting it via this method.
         *
         * @param bean the bean instantiated (or found) that corresponds to this BeanConfiguration instance.
         */
        public void setBean(Object bean) {
            this.bean = bean;
        }

        public Object getBean() {
            return this.bean;
        }

        /**
         * Returns true if all configuration statements have been executed.
         * @return true if all configuration statements have been executed.
         */
        public boolean isExecuted() {
            if (instantiationStatement != null && !instantiationStatement.isExecuted()) {
                return false;
            }
            for (AssignmentStatement as : assignments) {
                if (!as.isExecuted()) {
                    return false;
                }
            }
            return true;
        }
    }

    private abstract class Statement {

        protected final String lhs;
        protected final String rhs;
        protected Object bean;
        private Object result;
        private boolean executed;
        private BeanConfiguration beanConfiguration;

        private Statement(String lhs, String rhs) {
            this.lhs = lhs;
            this.rhs = rhs;
            this.executed = false;
        }

        public void setBeanConfiguration(BeanConfiguration bd) {
            this.beanConfiguration = bd;
        }

        public BeanConfiguration getBeanConfiguration() {
            return this.beanConfiguration;
        }

        public Object execute() {
            if (!isExecuted()) {
                this.result = doExecute();
                this.executed = true;
            }
            if (!getBeanConfiguration().isGlobalConfig()) {
                Assert.notNull(this.bean, "Implementation must set the root bean for which it executed.");
            }
            return this.result;
        }

        public Object getBean() {
            return this.bean;
        }

        protected void setBean(Object bean) {
            this.bean = bean;
            if (this.beanConfiguration.getBean() == null) {
                this.beanConfiguration.setBean(bean);
            }
        }

        public Object getResult() {
            return result;
        }

        protected abstract Object doExecute();

        public boolean isExecuted() {
            return executed;
        }
    }

    private class InstantiationStatement extends Statement {

        private InstantiationStatement(String lhs, String rhs) {
            super(lhs, rhs);
        }

        @Override
        protected Object doExecute() {
            String beanName = this.lhs;
            createNewInstance(objects, beanName, this.rhs);
            Object instantiated = objects.get(beanName);
            setBean(instantiated);

            //also ensure the instantiated bean has access to the event bus or is subscribed to events if necessary:
            //Note: because events are being enabled on this bean here (before the instantiated event below is
            //triggered), beans can react to their own instantiation events.
            enableEventsIfNecessary(instantiated, beanName);

            BeanEvent event = new InstantiatedBeanEvent(beanName, instantiated, Collections.unmodifiableMap(objects));
            eventBus.publish(event);

            return instantiated;
        }
    }

    private class AssignmentStatement extends Statement {

        private final String rootBeanName;

        private AssignmentStatement(String lhs, String rhs) {
            super(lhs, rhs);
            int index = lhs.indexOf('.');
            this.rootBeanName = lhs.substring(0, index);
        }

        @Override
        protected Object doExecute() {
            applyProperty(lhs, rhs, objects);
            Object bean = objects.get(this.rootBeanName);
            setBean(bean);
            return null;
        }

        public String getRootBeanName() {
            return this.rootBeanName;
        }
    }

    //////////////////////////
    // From CollectionUtils //
    //////////////////////////
    // CollectionUtils cannot be removed from shiro-core until 2.0 as it has a dependency on PrincipalCollection

    private static boolean isEmpty(Map m) {
        return m == null || m.isEmpty();
    }

    private static boolean isEmpty(Collection c) {
        return c == null || c.isEmpty();
    }

}
