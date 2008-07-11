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
package org.jsecurity.samples.sprhib.eis.hibernate;

import org.hibernate.Filter;
import org.hibernate.LockMode;
import org.hibernate.ReplicationMode;
import org.hibernate.criterion.DetachedCriteria;
import org.jsecurity.samples.sprhib.eis.DataAccessObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.orm.hibernate3.HibernateCallback;
import org.springframework.orm.hibernate3.HibernateOperations;
import org.springframework.orm.hibernate3.support.HibernateDaoSupport;

import java.io.Serializable;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * Simplifies hibernate usage and enhances readability for subclasses so they don't have to call
 * <code>getHibernateTemplate()</code> for every Hibernate operation.
 *
 * @author Les Hazlewood
 */
public class HibernateDAO extends HibernateDaoSupport
        implements HibernateOperations, DataAccessObject {

    protected final transient Logger log = LoggerFactory.getLogger(getClass());

    public Object execute(HibernateCallback action) throws DataAccessException {
        return getHibernateTemplate().execute(action);
    }

    public List executeFind(HibernateCallback action) throws DataAccessException {
        return getHibernateTemplate().executeFind(action);
    }

    public Object get(Class entityClass, Serializable id) throws DataAccessException {
        return getHibernateTemplate().get(entityClass, id);
    }

    public Object get(Class entityClass, Serializable id, LockMode lockMode)
            throws DataAccessException {
        return getHibernateTemplate().get(entityClass, id, lockMode);
    }

    public Object get(String entityName, Serializable id) throws DataAccessException {
        return getHibernateTemplate().get(entityName, id);
    }

    public Object get(String entityName, Serializable id, LockMode lockMode)
            throws DataAccessException {
        return getHibernateTemplate().get(entityName, id, lockMode);
    }

    public Object load(Class entityClass, Serializable id) throws DataAccessException {
        return getHibernateTemplate().load(entityClass, id);
    }

    public Object load(Class entityClass, Serializable id, LockMode lockMode)
            throws DataAccessException {
        return getHibernateTemplate().load(entityClass, id, lockMode);
    }

    public Object load(String entityName, Serializable id) throws DataAccessException {
        return getHibernateTemplate().load(entityName, id);
    }

    public Object load(String entityName, Serializable id, LockMode lockMode)
            throws DataAccessException {
        return getHibernateTemplate().load(entityName, id, lockMode);
    }

    public List loadAll(Class entityClass) throws DataAccessException {
        return getHibernateTemplate().loadAll(entityClass);
    }

    public void load(Object entity, Serializable id) throws DataAccessException {
        getHibernateTemplate().load(entity, id);
    }

    public void refresh(Object entity) throws DataAccessException {
        getHibernateTemplate().refresh(entity);
    }

    public void refresh(Object entity, LockMode lockMode) throws DataAccessException {
        getHibernateTemplate().refresh(entity, lockMode);
    }

    public boolean contains(Object entity) throws DataAccessException {
        return getHibernateTemplate().contains(entity);
    }

    public void evict(Object entity) throws DataAccessException {
        getHibernateTemplate().evict(entity);
    }

    public void initialize(Object proxy) throws DataAccessException {
        getHibernateTemplate().initialize(proxy);
    }

    public Filter enableFilter(String string) throws IllegalStateException {
        return getHibernateTemplate().enableFilter(string);
    }

    public void lock(Object entity, LockMode lockMode) throws DataAccessException {
        getHibernateTemplate().lock(entity, lockMode);
    }

    public void lock(String entityName, Object entity, LockMode lockMode)
            throws DataAccessException {
        getHibernateTemplate().lock(entityName, entity, lockMode);
    }

    public Serializable create(Object entity) {
        return save(entity);
    }

    public Serializable save(Object entity) throws DataAccessException {
        return getHibernateTemplate().save(entity);
    }

    public Serializable save(String entityName, Object entity) throws DataAccessException {
        return getHibernateTemplate().save(entityName, entity);
    }

    public void update(Object entity) throws DataAccessException {
        getHibernateTemplate().update(entity);
    }

    public void update(Object entity, LockMode lockMode) throws DataAccessException {
        getHibernateTemplate().update(entity, lockMode);
    }

    public void update(String entityName, Object entity) throws DataAccessException {
        getHibernateTemplate().update(entityName, entity);
    }

    public void update(String entityName, Object entity, LockMode lockMode)
            throws DataAccessException {
        getHibernateTemplate().update(entityName, entity, lockMode);
    }

    public void saveOrUpdate(Object entity) throws DataAccessException {
        getHibernateTemplate().saveOrUpdate(entity);
    }

    public void saveOrUpdate(String entityName, Object entity) throws DataAccessException {
        getHibernateTemplate().saveOrUpdate(entityName, entity);
    }

    public void saveOrUpdateAll(Collection entities) throws DataAccessException {
        getHibernateTemplate().saveOrUpdateAll(entities);
    }

    public void replicate(Object object, ReplicationMode replicationMode) throws DataAccessException {
        getHibernateTemplate().replicate(object, replicationMode);
    }

    public void replicate(String string, Object object, ReplicationMode replicationMode) throws DataAccessException {
        getHibernateTemplate().replicate(string, object, replicationMode);
    }

    public void persist(Object entity) throws DataAccessException {
        getHibernateTemplate().persist(entity);
    }

    public void persist(String entityName, Object entity) throws DataAccessException {
        getHibernateTemplate().persist(entityName, entity);
    }

    public Object merge(Object entity) throws DataAccessException {
        return getHibernateTemplate().merge(entity);
    }

    public Object merge(String entityName, Object entity) throws DataAccessException {
        return getHibernateTemplate().merge(entityName, entity);
    }

    public void delete(Object entity) throws DataAccessException {
        getHibernateTemplate().delete(entity);
    }

    public void delete(Object entity, LockMode lockMode) throws DataAccessException {
        getHibernateTemplate().delete(entity, lockMode);
    }

    public void delete(String s, Object o) throws DataAccessException {
        getHibernateTemplate().delete(s, o);
    }

    public void delete(String s, Object o, LockMode lockMode) throws DataAccessException {
        getHibernateTemplate().delete(s, o, lockMode);
    }

    public void deleteById(Class entityType, Serializable id) {
        delete(load(entityType, id));
    }

    public void delete(Collection entities) {
        deleteAll(entities);
    }

    public void deleteAll(Collection entities) throws DataAccessException {
        getHibernateTemplate().deleteAll(entities);
    }

    public void flush() throws DataAccessException {
        getHibernateTemplate().flush();
    }

    public void clear() throws DataAccessException {
        getHibernateTemplate().clear();
    }

    public List find(String queryString) throws DataAccessException {
        return getHibernateTemplate().find(queryString);
    }

    public List find(String queryString, Object value) throws DataAccessException {
        return getHibernateTemplate().find(queryString, value);
    }

    public List find(String queryString, Object[] values) throws DataAccessException {
        return getHibernateTemplate().find(queryString, values);
    }

    /**
     * Execute a query for persistent instances expecting only a single result.  If no results
     * are returned from the query, this method returns <tt>null</tt>.
     *
     * @param queryString a query expressed in Hibernate's query language
     * @return the single object returned from the query, or <tt>null</tt> if no results were
     *         returned from the query.
     * @throws org.springframework.dao.IncorrectResultSizeDataAccessException
     *          if more than 1 result is returned
     * @throws org.springframework.dao.DataAccessException
     *          in case of Hibernate errors
     * @see org.hibernate.Session#createQuery
     */
    public Object findSingle(String queryString) throws DataAccessException {
        return findSingle(queryString, (Object[]) null);
    }

    /**
     * Execute a query expecting a single persistent instance, binding
     * one value to a "?" parameter in the query string.
     *
     * @param queryString a query expressed in Hibernate's query language
     * @param value       the value of the parameter
     * @return the single object returned from the query, or <tt>null</tt> if no results were
     *         returned from the query.
     * @throws org.springframework.dao.IncorrectResultSizeDataAccessException
     *          if more than 1 result is returned
     * @throws org.springframework.dao.DataAccessException
     *          in case of Hibernate errors
     * @see org.hibernate.Session#createQuery
     */
    public Object findSingle(String queryString, Object value) {
        return findSingle(queryString, new Object[]{value});
    }

    /**
     * Execute a query expecting a single persistent instance, binding a
     * number of values to "?" parameters in the query string.
     *
     * @param queryString a query expressed in Hibernate's query language
     * @param values      the values of the parameters
     * @return the single object returned from the query, or <tt>null</tt> if no results were
     *         returned from the query.
     * @throws org.springframework.dao.IncorrectResultSizeDataAccessException
     *          if more than 1 result is returned
     * @throws org.springframework.dao.DataAccessException
     *          in case of Hibernate errors
     * @see org.hibernate.Session#createQuery
     */
    public Object findSingle(String queryString, Object[] values) throws DataAccessException {
        List results = find(queryString, values);

        if (results != null && !results.isEmpty()) {
            return results.get(0);
        }

        return null;
    }

    public List findByCriteria(DetachedCriteria criteria) throws DataAccessException {
        return getHibernateTemplate().findByCriteria(criteria);
    }

    public List findByCriteria(DetachedCriteria criteria, int firstResult, int maxResults)
            throws DataAccessException {
        return getHibernateTemplate().findByCriteria(criteria, firstResult, maxResults);
    }

    public List findByExample(Object object) throws DataAccessException {
        return getHibernateTemplate().findByExample(object);
    }

    public List findByExample(Object object, int i, int i1) throws DataAccessException {
        return getHibernateTemplate().findByExample(object, i, i1);
    }

    public List findByExample(String entityName, Object exampleEntity) throws DataAccessException {
        return getHibernateTemplate().findByExample(entityName, exampleEntity);
    }

    public List findByExample(String entityName, Object exampleEntity, int firstResult, int maxResults) throws DataAccessException {
        return getHibernateTemplate().findByExample(entityName, exampleEntity, firstResult, maxResults);
    }

    public List findByNamedParam(String queryName, String paramName, Object value)
            throws DataAccessException {
        return getHibernateTemplate().findByNamedParam(queryName, paramName, value);
    }

    public List findByNamedParam(String queryString, String[] paramNames, Object[] values)
            throws DataAccessException {
        return getHibernateTemplate().findByNamedParam(queryString, paramNames, values);
    }

    public List findByValueBean(String queryString, Object valueBean) throws DataAccessException {
        return getHibernateTemplate().findByValueBean(queryString, valueBean);
    }

    public List findByNamedQuery(String queryName) throws DataAccessException {
        return getHibernateTemplate().findByNamedQuery(queryName);
    }

    public List findByNamedQuery(String queryName, Object value) throws DataAccessException {
        return getHibernateTemplate().findByNamedQuery(queryName, value);
    }

    public List findByNamedQuery(String queryName, Object[] values) throws DataAccessException {
        return getHibernateTemplate().findByNamedQuery(queryName, values);
    }

    public List findByNamedQueryAndNamedParam(String queryName, String paramName, Object value)
            throws DataAccessException {
        return getHibernateTemplate().findByNamedQueryAndNamedParam(queryName, paramName, value);
    }

    public List findByNamedQueryAndNamedParam(String queryName, String[] paramNames,
                                              Object[] values) throws DataAccessException {
        return getHibernateTemplate().findByNamedQueryAndNamedParam(queryName, paramNames, values);
    }

    public List findByNamedQueryAndValueBean(String queryName, Object valueBean)
            throws DataAccessException {
        return getHibernateTemplate().findByNamedQueryAndValueBean(queryName, valueBean);
    }

    public Iterator iterate(String queryString) throws DataAccessException {
        return getHibernateTemplate().iterate(queryString);
    }

    public Iterator iterate(String queryString, Object value) throws DataAccessException {
        return getHibernateTemplate().iterate(queryString, value);
    }

    public Iterator iterate(String queryString, Object[] values) throws DataAccessException {
        return getHibernateTemplate().iterate(queryString, values);
    }

    public void closeIterator(Iterator it) throws DataAccessException {
        getHibernateTemplate().closeIterator(it);
    }

    public int bulkUpdate(String string) throws DataAccessException {
        return getHibernateTemplate().bulkUpdate(string);
    }

    public int bulkUpdate(String string, Object object) throws DataAccessException {
        return getHibernateTemplate().bulkUpdate(string, object);
    }

    public int bulkUpdate(String string, Object[] objects) throws DataAccessException {
        return getHibernateTemplate().bulkUpdate(string, objects);
    }

}



