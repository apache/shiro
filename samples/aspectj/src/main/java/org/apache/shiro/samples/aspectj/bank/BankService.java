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

import java.util.Date;

public interface BankService {

    long[] searchAccountIdsByOwner(String anOwnerName);

    long createNewAccount(String anOwnerName);

    double getBalanceOf(long anAccountId) throws AccountNotFoundException;

    String getOwnerOf(long anAccountId) throws AccountNotFoundException;

    double depositInto(long anAccountId, double anAmount) throws AccountNotFoundException, InactiveAccountException;

    double withdrawFrom(long anAccountId, double anAmount) throws AccountNotFoundException, NotEnoughFundsException, InactiveAccountException;

    TxLog[] getTxHistoryFor(long anAccountId) throws AccountNotFoundException;

    double closeAccount(long anAccountId) throws AccountNotFoundException, InactiveAccountException;

    boolean isAccountActive(long anAccountId) throws AccountNotFoundException;

    class TxLog {
        private Date creationDate;
        private double amount;
        private String madeBy;

        public TxLog(Date aCreationDate, double aAmount, String aMadeBy) {
            super();
            creationDate = aCreationDate;
            amount = aAmount;
            madeBy = aMadeBy;
        }

        /**
         * Returns the creationDate attribute.
         *
         * @return The creationDate value.
         */
        public Date getCreationDate() {
            return creationDate;
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
         * Returns the madeBy attribute.
         *
         * @return The madeBy value.
         */
        public String getMadeBy() {
            return madeBy;
        }
    }

}
