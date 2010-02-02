package org.apache.shiro.sample.bank;


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
