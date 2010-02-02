package org.apache.shiro.sample.bank;


import java.sql.Timestamp;
import java.util.Date;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

public class AccountTransaction {

  private static long _SEQUENCE;
  
  public enum TransactionType {
    DEPOSIT,
    WITHDRAWAL;
  }
  
  private long _id;
  
  private TransactionType _type;
  
  private long _accountId;
  
  private double _amount;
  
  private String _createdBy;
  private Date _creationDate;
  
  public static AccountTransaction createDepositTx(long anAccountId, double anAmount) {
    AccountTransaction tx = new AccountTransaction(TransactionType.DEPOSIT, anAccountId, anAmount);
    return tx;
  }
  
  public static AccountTransaction createWithdrawalTx(long anAccountId, double anAmount) {
    AccountTransaction tx = new AccountTransaction(TransactionType.WITHDRAWAL, anAccountId, anAmount);
    return tx;
  }
  
  private AccountTransaction(TransactionType aType, long anAccountId, double anAmount) {
    _id = ++_SEQUENCE;
    _type = aType;
    _accountId = anAccountId;
    _amount = anAmount;
    _createdBy = "unknown";
    _creationDate = new Date();
  }

  /**
   * Returns the id attribute.
   *
   * @return The id value.
   */
  public long getId() {
    return _id;
  }

  /**
   * Returns the type attribute.
   *
   * @return The type value.
   */
  public TransactionType getType() {
    return _type;
  }

  /**
   * Returns the accountId attribute.
   *
   * @return The accountId value.
   */
  public long getAccountId() {
    return _accountId;
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
   * Changes the value of the attributes createdBy.
   *
   * @param aCreatedBy The new value of the createdBy attribute.
   */
  protected void setCreatedBy(String aCreatedBy) {
    _createdBy = aCreatedBy;
  }

  /**
   * Returns the createdBy attribute.
   *
   * @return The createdBy value.
   */
  public String getCreatedBy() {
    return _createdBy;
  }

  /**
   * Returns the creationDate attribute.
   *
   * @return The creationDate value.
   */
  public Date getCreationDate() {
    return _creationDate;
  }
  
  /* (non-Javadoc)
   * @see java.lang.Object#toString()
   */
  public String toString() {
    return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).
            append("id", _id).
            append("type", _type).
            append("accountId", _accountId).
            append("amount", _amount).
            append("createdBy", _createdBy).
            append("creationDate", new Timestamp(_creationDate.getTime())).
            toString();
  }
  
}
