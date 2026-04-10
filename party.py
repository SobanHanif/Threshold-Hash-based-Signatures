# A proposed framework for representing parties and coordinators
import secrets
import threshold
from abc import ABC, abstractmethod

class Party:
  def __init__(self):
    # the random number each party holds
    self._share = secrets.token_bytes(32)

  @property
  def share(self):
    return self.share
  

class Controller:
  # partyList: list of all n - 1 other parties, secret key is the 256 pairs from earlier
  def __init__(self, partyList: list[Party], secret_key: list[list[int]], n: int):
    # the share is construct
    self.share = self.__constructShare(partyList, secret_key, n)

  def __constructShare(self, partyList: list[Party], secret_key: list[list[int]], n: int):
    # r_n = s1[0] r1r2  rn-1

    # get all the shares from before
    shares = [party.share for party in partyList]

    # this is the xor for our conttroller class
    last_share = []
    for i in range(256):
        p0, p1 = secret_key[i][0], secret_key[i][1]
        for j in range(n - 1):
            p0 = threshold.xor_bytes(p0, shares[j])
            p1 = threshold.xor_bytes(p1, shares[j])
        last_share.append([p0, p1])
    
    return last_share

  @property
  def share(self):
    return self.share




  