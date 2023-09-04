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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.samples.aspectj.bank.AccountTransaction.TransactionType;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SecureBankService implements BankService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecureBankService.class);
    private volatile boolean isRunning;
    private final List<Account> accounts;
    private Map<Long, Account> accountsById;

    /**
     * Creates a new {@link SecureBankService} instance.
     */
    public SecureBankService() {
        accounts = new ArrayList<Account>();
        accountsById = new HashMap<Long, Account>();
    }

    /**
     * Starts this service
     */
    public void start() throws Exception {
        isRunning = true;
        LOGGER.info("Bank service started");
    }

    /**
     * Stop this service
     */
    public void dispose() {
        LOGGER.info("Stopping bank service...");
        isRunning = false;

        synchronized (accounts) {
            accountsById.clear();
            accounts.clear();
        }

        LOGGER.info("Bank service stopped");
    }

    /**
     * Internal utility method that validate the internal state of this service.
     */
    protected void assertServiceState() {
        if (!isRunning) {
            throw new IllegalStateException("This bank service is not running");
        }
    }

    public int getAccountCount() {
        return accounts.size();
    }

    /* (non-Javadoc)
    * @see com.connectif.trilogy.root.security.BankService#createNewAccount(java.lang.String)
    */

    @RequiresPermissions("bankAccount:create")
    public long createNewAccount(String anOwnerName) {
        assertServiceState();
        LOGGER.info("Creating new account for " + anOwnerName);

        synchronized (accounts) {
            Account account = new Account(anOwnerName);
            account.setCreatedBy(getCurrentUsername());
            accounts.add(account);
            accountsById.put(account.getId(), account);

            LOGGER.debug("Created new account: " + account);
            return account.getId();
        }
    }

    /* (non-Javadoc)
    * @see com.connectif.trilogy.root.security.BankService#searchAccountIdsByOwner(java.lang.String)
    */

    public long[] searchAccountIdsByOwner(String anOwnerName) {
        assertServiceState();
        LOGGER.info("Searching existing accounts for " + anOwnerName);

        ArrayList<Account> matchAccounts = new ArrayList<Account>();
        synchronized (accounts) {
            for (Account a : accounts) {
                if (a.getOwnerName().toLowerCase().contains(anOwnerName.toLowerCase())) {
                    matchAccounts.add(a);
                }
            }
        }

        long[] accountIds = new long[matchAccounts.size()];
        int index = 0;
        for (Account a : matchAccounts) {
            accountIds[index++] = a.getId();
        }

        LOGGER.debug("Found " + accountIds.length + " account(s) matching the name " + anOwnerName);
        return accountIds;
    }

    /* (non-Javadoc)
    * @see com.connectif.trilogy.root.security.BankService#getOwnerOf(long)
    */

    @RequiresPermissions("bankAccount:read")
    public String getOwnerOf(long anAccountId) throws AccountNotFoundException {
        assertServiceState();
        LOGGER.info("Getting owner of account " + anAccountId);

        Account a = safelyRetrieveAccountForId(anAccountId);
        return a.getOwnerName();
    }

    /* (non-Javadoc)
    * @see com.connectif.trilogy.root.security.BankService#getBalanceOf(long)
    */

    @RequiresPermissions("bankAccount:read")
    public double getBalanceOf(long anAccountId) throws AccountNotFoundException {
        assertServiceState();
        LOGGER.info("Getting balance of account " + anAccountId);

        Account a = safelyRetrieveAccountForId(anAccountId);
        return a.getBalance();
    }

    /* (non-Javadoc)
    * @see com.connectif.trilogy.root.security.BankService#depositInto(long, double)
    */

    @RequiresPermissions("bankAccount:operate")
    public double depositInto(long anAccountId, double anAmount) throws AccountNotFoundException, InactiveAccountException {
        assertServiceState();
        LOGGER.info("Making deposit of " + anAmount + " into account " + anAccountId);

        try {
            Account a = safelyRetrieveAccountForId(anAccountId);
            AccountTransaction tx = AccountTransaction.createDepositTx(anAccountId, anAmount);
            tx.setCreatedBy(getCurrentUsername());
            LOGGER.debug("Created a new transaction " + tx);

            a.applyTransaction(tx);
            LOGGER.debug("New balance of account " + a.getId() + " after deposit is " + a.getBalance());

            return a.getBalance();

        } catch (NotEnoughFundsException nefe) {
            throw new IllegalStateException("Should never happen", nefe);
        }
    }

    /* (non-Javadoc)
    * @see com.connectif.trilogy.root.security.BankService#withdrawFrom(long, double)
    */

    @RequiresPermissions("bankAccount:operate")
    public double withdrawFrom(long anAccountId, double anAmount) throws AccountNotFoundException, NotEnoughFundsException, InactiveAccountException {
        assertServiceState();
        LOGGER.info("Making withdrawal of " + anAmount + " from account " + anAccountId);

        Account a = safelyRetrieveAccountForId(anAccountId);
        AccountTransaction tx = AccountTransaction.createWithdrawalTx(anAccountId, anAmount);
        tx.setCreatedBy(getCurrentUsername());
        LOGGER.debug("Created a new transaction " + tx);

        a.applyTransaction(tx);
        LOGGER.debug("New balance of account " + a.getId() + " after withdrawal is " + a.getBalance());

        return a.getBalance();
    }

    /* (non-Javadoc)
    * @see com.connectif.trilogy.root.security.BankService#getTxHistoryFor(long)
    */

    @RequiresPermissions("bankAccount:read")
    public TxLog[] getTxHistoryFor(long anAccountId) throws AccountNotFoundException {
        assertServiceState();
        LOGGER.info("Getting transactions of account " + anAccountId);

        Account a = safelyRetrieveAccountForId(anAccountId);

        TxLog[] txs = new TxLog[a.getTransactions().size()];
        int index = 0;
        for (AccountTransaction tx : a.getTransactions()) {
            LOGGER.debug("Retrieved transaction " + tx);

            if (TransactionType.DEPOSIT == tx.getType()) {
                txs[index++] = new TxLog(tx.getCreationDate(), tx.getAmount(), tx.getCreatedBy());
            } else {
                txs[index++] = new TxLog(tx.getCreationDate(), -1.0d * tx.getAmount(), tx.getCreatedBy());
            }
        }

        return txs;
    }

    /* (non-Javadoc)
    * @see com.connectif.trilogy.root.security.BankService#closeAccount(long)
    */

    @RequiresPermissions("bankAccount:close")
    public double closeAccount(long anAccountId) throws AccountNotFoundException, InactiveAccountException {
        assertServiceState();
        LOGGER.info("Closing account " + anAccountId);

        Account a = safelyRetrieveAccountForId(anAccountId);
        if (!a.isActive()) {
            throw new InactiveAccountException("The account " + anAccountId + " is already closed");
        }

        try {
            AccountTransaction tx = AccountTransaction.createWithdrawalTx(a.getId(), a.getBalance());
            tx.setCreatedBy(getCurrentUsername());
            LOGGER.debug("Created a new transaction " + tx);
            a.applyTransaction(tx);
            a.setActive(false);

            LOGGER.debug("Account " + a.getId() + " is now closed and an amount of " + tx.getAmount() + " is given to the owner");
            return tx.getAmount();

        } catch (NotEnoughFundsException nefe) {
            throw new IllegalStateException("Should never happen", nefe);
        }
    }

    /* (non-Javadoc)
    * @see com.connectif.trilogy.root.security.BankService#isAccountActive(long)
    */

    @RequiresPermissions("bankAccount:read")
    public boolean isAccountActive(long anAccountId) throws AccountNotFoundException {
        assertServiceState();
        LOGGER.info("Getting active status of account " + anAccountId);

        Account a = safelyRetrieveAccountForId(anAccountId);
        return a.isActive();
    }


    /**
     * Internal method that safely (concurrency-wise) retrieves an account from the id passed in.
     *
     * @param anAccountId The identifier of the account to retrieve.
     * @return The account instance retrieved.
     * @throws AccountNotFoundException If no account is found for the provided identifier.
     */
    protected Account safelyRetrieveAccountForId(long anAccountId) throws AccountNotFoundException {
        Account account = null;
        synchronized (accounts) {
            account = accountsById.get(anAccountId);
        }

        if (account == null) {
            throw new AccountNotFoundException("No account found for the id " + anAccountId);
        }

        LOGGER.info("Retrieved account " + account);
        return account;
    }

    /**
     * Internal utility method to retrieve the username of the current authenticated user.
     *
     * @return The name.
     */
    protected String getCurrentUsername() {
        Subject subject = SecurityUtils.getSubject();
        if (subject == null || subject.getPrincipal() == null || !subject.isAuthenticated()) {
            throw new IllegalStateException("Unable to retrieve the current authenticated subject");
        }
        return SecurityUtils.getSubject().getPrincipal().toString();
    }
}
