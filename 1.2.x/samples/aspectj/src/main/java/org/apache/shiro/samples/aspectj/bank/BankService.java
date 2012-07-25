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

    public long[] searchAccountIdsByOwner(String anOwnerName);

    public long createNewAccount(String anOwnerName);

    public double getBalanceOf(long anAccountId) throws AccountNotFoundException;

    public String getOwnerOf(long anAccountId) throws AccountNotFoundException;

    public double depositInto(long anAccountId, double anAmount) throws AccountNotFoundException, InactiveAccountException;

    public double withdrawFrom(long anAccountId, double anAmount) throws AccountNotFoundException, NotEnoughFundsException, InactiveAccountException;

    public TxLog[] getTxHistoryFor(long anAccountId) throws AccountNotFoundException;

    public double closeAccount(long anAccountId) throws AccountNotFoundException, InactiveAccountException;

    public boolean isAccountActive(long anAccountId) throws AccountNotFoundException;

    public static class TxLog {
        private Date _creationDate;
        private double _amount;
        private String _madeBy;

        public TxLog(Date aCreationDate, double aAmount, String aMadeBy) {
            super();
            _creationDate = aCreationDate;
            _amount = aAmount;
            _madeBy = aMadeBy;
        }

        /**
         * Returns the creationDate attribute.
         *
         * @return The creationDate value.
         */
        public Date getCreationDate() {
            return _creationDate;
        }

        /**
         * Returns the amount attribute.
         *
         * @return The amount value.
         */
        public double getAmount() {
            return _amount;
        }

        /**
         * Returns the madeBy attribute.
         *
         * @return The madeBy value.
         */
        public String getMadeBy() {
            return _madeBy;
        }
    }

}
