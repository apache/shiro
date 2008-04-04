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
package org.jsecurity.subject;

import java.util.*;

/**
 * @since 0.9
 * @author Les Hazlewood
 */
@SuppressWarnings({"unchecked"})
public class SimplePrincipalCollection implements PrincipalCollection {

    private Map<String,Set> realmPrincipals;

    public SimplePrincipalCollection(){}

    public SimplePrincipalCollection( String realmName, Object principal ) {
        add(realmName, principal);
    }

    public SimplePrincipalCollection( String realmName, Collection principals ) {
        add(realmName, principals);
    }

    protected Collection getPrincipalsLazy( String realmName ) {
        if ( realmPrincipals == null ) {
            realmPrincipals = new LinkedHashMap<String,Set>();
        }
        Set principals = realmPrincipals.get( realmName );
        if ( principals == null ) {
            principals = new LinkedHashSet();
            realmPrincipals.put(realmName, principals );
        }
        return principals;
    }

    public void add( String realmName, Object principal ) {
        if ( realmName == null ) {
            throw new IllegalArgumentException( "realmName argument cannot be null." );
        }
        if ( principal == null ) {
            throw new IllegalArgumentException( "principal argument cannot be null." );
        }
        getPrincipalsLazy(realmName).add(principal);
    }

    public void add( String realmName, Collection principals ) {
        if ( realmName == null ) {
            throw new IllegalArgumentException( "realmName argument cannot be null." );
        }
        if ( principals == null ) {
            throw new IllegalArgumentException( "principals argument cannot be null." );
        }
        if ( principals.isEmpty() ) {
            throw new IllegalArgumentException( "principals argument cannot be an empty collection." );
        }
        getPrincipalsLazy(realmName).addAll(principals);
    }

    public <T> T oneByType(Class<T> type) {
        if ( realmPrincipals == null || realmPrincipals.isEmpty() ) {
            return null;
        }
        Collection<Set> values = realmPrincipals.values();
        for ( Set set : values ) {
            for( Object o : set ) {
                if ( type.isAssignableFrom(o.getClass()) ) {
                    return (T)o;
                }
            }
        }
        return null;
    }

    public <T> Collection<T> byType(Class<T> type) {
        if ( realmPrincipals == null || realmPrincipals.isEmpty() ) {
            return Collections.EMPTY_SET;
        }
        Set<T> typed = new LinkedHashSet<T>();
        Collection<Set> values = realmPrincipals.values();
        for ( Set set : values ) {
            for( Object o : set ) {
                if ( type.isAssignableFrom(o.getClass()) ) {
                    typed.add((T)o);
                }
            }
        }
        if ( typed.isEmpty() ) {
            return Collections.EMPTY_SET;
        }
        return Collections.unmodifiableSet(typed);
    }

    public List asList() {
        Set all = asSet();
        if ( all.isEmpty() ) {
            return Collections.EMPTY_LIST;
        }
        return Collections.unmodifiableList( new ArrayList(all) );
    }

    public Set asSet() {
        if ( realmPrincipals == null || realmPrincipals.isEmpty() ) {
            return Collections.EMPTY_SET;
        }
        Set aggregated = new LinkedHashSet();
        Collection<Set> values = realmPrincipals.values();
        for ( Set set : values ) {
            aggregated.addAll(set);
        }
        if ( aggregated.isEmpty() ) {
            return Collections.EMPTY_SET;
        }
        return Collections.unmodifiableSet(aggregated);
    }

    public Collection fromRealm(String realmName) {
        if ( realmPrincipals == null || realmPrincipals.isEmpty() ) {
            return Collections.EMPTY_SET;
        }
        Set principals = realmPrincipals.get(realmName);
        if ( principals == null || principals.isEmpty() ) {
            principals = Collections.EMPTY_SET;
        }
        return Collections.unmodifiableSet(principals);
    }

    public boolean isEmpty() {
        return realmPrincipals == null || realmPrincipals.isEmpty();
    }

    public void clear() {
        if ( realmPrincipals != null ) {
            realmPrincipals.clear();
            realmPrincipals = null;
        }
    }

    public Iterator iterator() {
        return asSet().iterator();
    }

    public void merge( SimplePrincipalCollection principals ) {
        if ( principals == null || principals.isEmpty() ) {
            return;
        }
        if ( this.realmPrincipals == null || this.realmPrincipals.isEmpty() ) {
            this.realmPrincipals = principals.realmPrincipals;
            return;
        }

        for( String realmName : principals.realmPrincipals.keySet() ) {
            Collection realmPrincipals = principals.realmPrincipals.get(realmName);
            if ( realmPrincipals != null && !realmPrincipals.isEmpty() ) {
                for( Object principal : realmPrincipals ) {
                    add( realmName, principal );
                }
            }
        }
    }
}
