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
import java.util.Date;

public final class AccountTransaction {

    private static long sequence;

    public enum TransactionType {
        /**
         * deposit.
         */
        DEPOSIT,
        /**
         * withdrawal.
         */
        WITHDRAWAL
    }

    private long id;

    private TransactionType type;

    private long accountId;

    private double amount;

    private String createdBy;

    private Date creationDate;

    private AccountTransaction(TransactionType aType, long anAccountId, double anAmount) {
        id = ++sequence;
        type = aType;
        accountId = anAccountId;
        amount = anAmount;
        createdBy = "unknown";
        creationDate = new Date();
    }

    public static AccountTransaction createDepositTx(long anAccountId, double anAmount) {
        return new AccountTransaction(TransactionType.DEPOSIT, anAccountId, anAmount);
    }

    public static AccountTransaction createWithdrawalTx(long anAccountId, double anAmount) {
        return new AccountTransaction(TransactionType.WITHDRAWAL, anAccountId, anAmount);
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
     * Returns the type attribute.
     *
     * @return The type value.
     */
    public TransactionType getType() {
        return type;
    }

    /**
     * Returns the accountId attribute.
     *
     * @return The accountId value.
     */
    public long getAccountId() {
        return accountId;
    }

    /**
     * Returns the amount attribute.
     *
     * @return The amount value.
     */
    public double getAmount() {
        return amount;
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
                append("type", type).
                append("accountId", accountId).
                append("amount", amount).
                append("createdBy", createdBy).
                append("creationDate", new Timestamp(creationDate.getTime())).
                toString();
    }

}
