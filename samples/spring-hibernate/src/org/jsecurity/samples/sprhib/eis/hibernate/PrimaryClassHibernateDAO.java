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

import org.jsecurity.samples.sprhib.eis.PrimaryClassDAO;
import org.springframework.dao.DataAccessException;

import java.io.Serializable;
import java.util.List;

/**
 * @author Les Hazlewood
 */
public class PrimaryClassHibernateDAO extends HibernateDAO
        implements PrimaryClassDAO {

    protected Class primaryClass;

    public final Class getPrimaryClass() {
        return primaryClass;
    }

    public final void setPrimaryClass( Class clazz ) {
        primaryClass = clazz;
    }

    protected final void checkDaoConfiguration() throws Exception {
        if ( getPrimaryClass() == null ) {
            String msg = "Primary class property must be set";
            throw new IllegalArgumentException( msg );
        }
    }

    public Object read( Serializable entityId ) throws DataAccessException {
        return load( getPrimaryClass(), entityId );
    }


    public final List readAll() throws DataAccessException {
        return loadAll( getPrimaryClass() );
    }


    public void deleteById( final Serializable id ) throws DataAccessException {
        deleteById( getPrimaryClass(), id );
    }

    public void deleteAll() throws DataAccessException {
        deleteAll( readAll() );
    }

}
