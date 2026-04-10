# A proposed framework for representing parties and coordinators
import secrets
from abc import ABC, abstractmethod

class Party:
  def __init__(self):
    # the random number each party holds
    self.share = secrets.token_bytes(32)

  @property
  def share(self):
    return self.share
  

class Controller:
  def __init__(self, partyList: list[Party], secret: int):
    # the share is construct
    self.share = self.__constructShare(partyList, secret)

  def __constructShare(self, partyList: list[Party], secret: int):
    # r_n = s1[0] r1r2  rn-1
    share = secret
    for x in partyList[0:]:
      share ^= x
    return share
  
  @property
  def share(self):
    return self.share




  