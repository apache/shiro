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
package org.apache.shiro.samples.aspectj.bank;


import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class Account {

    private static long sequence;

    private long id;

    private String ownerName;

    private volatile boolean isActive;

    private double balance;

    private final List<AccountTransaction> transactionList;

    private String createdBy;

    private Date creationDate;

    public Account(String anOwnerName) {
        id = ++sequence;
        ownerName = anOwnerName;
        isActive = true;
        balance = 0.0d;
        transactionList = new ArrayList<AccountTransaction>();
        createdBy = "unknown";
        creationDate = new Date();
    }

    /**
     * Returns the id attribute.
     *
     * @return The id value.
     */
    public long getId() {
        return id;
    }

    /**
     * Returns the ownerName attribute.
     *
     * @return The ownerName value.
     */
    public String getOwnerName() {
        return ownerName;
    }

    /**
     * Returns the isActive attribute.
     *
     * @return The isActive value.
     */
    public boolean isActive() {
        return isActive;
    }

    /**
     * Changes the value of the attributes isActive.
     *
     * @param aIsActive The new value of the isActive attribute.
     */
    public void setActive(boolean aIsActive) {
        isActive = aIsActive;
    }

    /**
     * Changes the value of the attributes ownerName.
     *
     * @param aOwnerName The new value of the ownerName attribute.
     */
    public void setOwnerName(String aOwnerName) {
        ownerName = aOwnerName;
    }

    /**
     * Returns the balance attribute.
     *
     * @return The balance value.
     */
    public double getBalance() {
        return balance;
    }

    /**
     * Returns the transactions attribute.
     *
     * @return The transactions value.
     */
    public List<AccountTransaction> getTransactions() {
        return transactionList;
    }

    protected void applyTransaction(AccountTransaction aTransaction) throws NotEnoughFundsException, InactiveAccountException {
        if (!isActive) {
            throw new InactiveAccountException("Unable to apply "
                    + aTransaction.getType() + " of amount " + aTransaction.getAmount() + " to account " + id);
        }

        synchronized (transactionList) {
            if (AccountTransaction.TransactionType.DEPOSIT == aTransaction.getType()) {
                transactionList.add(aTransaction);
                balance += aTransaction.getAmount();

            } else if (AccountTransaction.TransactionType.WITHDRAWAL == aTransaction.getType()) {
                if (balance < aTransaction.getAmount()) {
                    throw new NotEnoughFundsException("Unable to withdraw "
                            + aTransaction.getAmount() + "$ from account " + id + " - current balance is " + balance);
                }
                transactionList.add(aTransaction);
                balance -= aTransaction.getAmount();

            } else {
                throw new IllegalArgumentException("The transaction passed in has an invalid type: " + aTransaction.getType());
            }
        }
    }

    /**
     * Changes the value of the attributes createdBy.
     *
     * @param aCreatedBy The new value of the createdBy attribute.
     */
    protected void setCreatedBy(String aCreatedBy) {
        createdBy = aCreatedBy;
    }

    /**
     * Returns the createdBy attribute.
     *
     * @return The createdBy value.
     */
    public String getCreatedBy() {
        return createdBy;
    }

    /**
     * Returns the creationDate attribute.
     *
     * @return The creationDate value.
     */
    public Date getCreationDate() {
        return creationDate;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */

    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).
                append("id", id).
                append("ownerName", ownerName).
                append("isActive", isActive).
                append("balance", balance).
                append("tx.count", transactionList.size()).
                append("createdBy", createdBy).
                append("creationDate", new Timestamp(creationDate.getTime())).
                toString();
    }
}
