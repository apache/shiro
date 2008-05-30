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
package org.jsecurity.config;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.util.ClassUtils;
import org.jsecurity.util.StringUtils;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * @since 0.9
 * @author Les Hazlewood
 */
public class ReflectionBuilder {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected Map<String,Object> objects = new LinkedHashMap<String,Object>();

    public ReflectionBuilder(){}

    public ReflectionBuilder( Map<String,Object> defaults ) {
        setObjects(defaults);
    }

    public Map<String, Object> getObjects() {
        return objects;
    }

    public void setObjects(Map<String, Object> objects) {
        this.objects = objects;
    }

    private static String[] splitKeyValue( String line ) {
        try {
            return StringUtils.splitKeyValue(line);
        } catch (ParseException e) {
            throw new ConfigurationException(e);
        }
    }

    public Map<String, Object> buildObjects(String config) {

        if (config == null) {
            return objects;
        }

        Scanner scanner = new Scanner(config);
        while (scanner.hasNextLine()) {

            String definitionLine = StringUtils.clean(scanner.nextLine());

            if (definitionLine != null && !definitionLine.startsWith("#")) {

                if (log.isTraceEnabled()) {
                    log.trace("Parsing definition line [" + definitionLine + "]");
                }

                String[] parts = splitKeyValue(definitionLine);
                if (parts == null || parts.length != 2) {
                    String msg = "Config parsing error - each configuration line must have the format:  key = value";
                    throw new IllegalStateException(msg);
                }

                String key = parts[0].trim();
                String value = parts[1].trim();

                applyProperty(key, value, objects);
            }

        }
        scanner.close();

        return objects;
    }

    public Map<String,Object> buildObjects( Map<String,String> kvPairs ) {
        if ( kvPairs == null || kvPairs.isEmpty() ) {
            return null;
        }
        for( Map.Entry<String,String> entry : kvPairs.entrySet() ) {
            applyProperty(entry.getKey(), entry.getValue(), objects );
        }

        return objects;
    }

    public void applyProperty(String key, String value, Map<String, Object> objects) {

        int index = key.indexOf('.');

        if (index >= 0) {
            String name = key.substring(0, index);
            String property = key.substring(index + 1, key.length());
            Object instance = objects.get(name);
            if (instance == null) {
                if (property.equals("class")) {
                    instance = ClassUtils.newInstance(value);
                    objects.put(name, instance);
                } else {
                    String msg = "Configuration error.  Specified object [" + name + "] with property [" +
                            property + "] without first defining that object's class.  Please first " +
                            "specify the class property first, e.g. myObject.class = fully_qualified_class_name " +
                            "and then define additional properties.";
                    throw new IllegalArgumentException(msg);
                }
            } else {
                applyProperty(instance, property, value);
            }
        } else {
            //no period, assume the prop is just the name only:
            Object instance = objects.get(key);
            if (instance == null) {
                //name with no property, assume right hand side of equals sign is the class name:
                try {
                    instance = ClassUtils.newInstance(value);
                } catch (Exception e) {
                    String msg = "Unable to instantiate class [" + value + "] for object named '" + key + "'.  " +
                            "Please ensure you've specified the fully qualified class name correctly.";
                    throw new ConfigurationException(msg, e);
                }
                objects.put(key, instance);
            }
        }
    }

    public void applyProperty(Object object, String propertyName, String value) {
        try {
            if (log.isTraceEnabled()) {
                log.trace("Applying property [" + propertyName + "] value [" + value + "] on object of type [" + object.getClass().getName() + "]");
            }
            BeanUtils.setProperty(object, propertyName, value);
        } catch (Exception e) {
            //perhaps the value was a reference to an object already defined:

            Object o = ( objects != null && !objects.isEmpty() ? objects.get(value) : null );
            if ( o != null ) {
                try {
                    BeanUtils.setProperty(object, propertyName, o );
                    return;
                } catch (Exception ignored) {}
            }

            String msg = "Unable to set property [" + propertyName + "] with value [" + value + "]";
            throw new ConfigurationException(msg, e);
        }
    }

}
