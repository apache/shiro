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
package org.apache.shiro.samples.sprhib.dao;

import org.apache.shiro.samples.sprhib.model.User;
import org.springframework.stereotype.Repository;
import org.springframework.util.Assert;

import java.util.List;

@Repository("userDAO")
@SuppressWarnings("unchecked")
public class HibernateUserDAO extends HibernateDao implements UserDAO {

    public User getUser(Long userId) {
        return (User) getSession().get(User.class, userId);
    }

    public User findUser(String username) {
        Assert.hasText(username);
        String query = "from User u where u.username = :username";
        return (User) getSession().createQuery(query).setString("username", username).uniqueResult();
    }

    public void createUser(User user) {
        getSession().save( user );
    }

    public List<User> getAllUsers() {
        return getSession().createQuery("from User order by username").list();
    }

    public void deleteUser(Long userId) {
        User user = getUser(userId);
        if( user != null ) {
            getSession().delete(user);
        }
    }

    public void updateUser(User user) {
        getSession().update(user);
    }

}

