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
package org.jsecurity.realm.jndi;

import org.jsecurity.jndi.JndiLocator;
import org.jsecurity.realm.Realm;
import org.jsecurity.realm.RealmFactory;
import org.jsecurity.util.StringUtils;

import javax.naming.NamingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * @author Les Hazlewood
 * @since Jun 24, 2008 5:11:28 PM
 */
public class JndiRealmFactory extends JndiLocator implements RealmFactory {

    Collection<String> jndiNames = null;

    public void setJndiNames(String commaDelimited) {
        String arg = StringUtils.clean(commaDelimited);
        String[] names = StringUtils.tokenizeToStringArray(arg, ",");
        this.jndiNames = Arrays.asList(names);
    }

    public Collection<Realm> getRealms() {
        List<Realm> realms = new ArrayList<Realm>();
        for (String name : this.jndiNames) {
            try {
                Realm realm = (Realm) lookup(name, Realm.class);
                realms.add(realm);
            } catch (NamingException e) {
                throw new IllegalStateException("Unable to look up realm with jndi name '" + name + "'.", e);
            }
        }
        return realms.isEmpty() ? null : realms;
    }
}
