#!/usr/bin/env python

from ledgerblue.comm import getDongle

import hashlib
import time, struct
import os.path
import logging

import ntrie


# Logs
FORMAT = '[%(asctime)-15s] %(message)s'
logging.basicConfig(filename='rng.log', level=logging.DEBUG, format=FORMAT)

dongle = getDongle(False)

# string x to hex padding it with a 0-bytes prefix if less than p bytes are given
def hencode(x, p):
  henc = x.encode('hex')
  return henc.zfill(p*2)

# interger to hex padding it with a 0-bytes prefix if less than p bytes are given
# iencode(17,8) -> '0000000000000011'
def iencode(i, p):
  if i == -1: i = 255 #FIXME
  res = hex(i).replace("0x", "").zfill(p*2)
  return res


def executeQueryInsert(depth, keyhash, valuehash, newhash, oldhash, sig, DT, RNONCE, NBYTES):
    return SEND("80"+"21"+iencode(depth, 1)+hencode(keyhash, 32)+hencode(valuehash, 32)+hencode(newhash, 32)+hencode(oldhash, 32)+hencode(sig, 70)+hencode(DT, 8)+hencode(RNONCE, 32)+iencode(NBYTES, 1))

SEND = lambda x: bytes(dongle.exchange(bytes(x.decode('hex'))))
SHA256 = lambda x: hashlib.sha256(x).digest()

def random_bytes(nbytes=32):

  # Check if monitoring have detected a broken Ledger
  if os.path.isfile('ledger_rng_behaving_unexpectedly'):
    logging.error("Unexpected Ledger behaviour, please check monitoring files.")
    return

  DT = 0*10 # number of ticks, NOT seconds
  RNONCE = "0"
  keyhash = hencode(str(int(time.time())),16) # does not need to be random but unique instead

  valuehash = SHA256("42") # in the first iteration, the value of valuehash is not important, it can be a random one but must be initialized

  # zero hash
  ZH = SHA256("\x00"*32)

  state = SEND("80"+"12") # export state to host
  ntrie.save_state(state)
  device_roothash = state[8+8:][:32]

  SEND("80"+"13"+state.encode('hex'))  # import state to the device

  # transfer data in 3 chunks (2bytes prefix + 16elementes*32bytes:
  setOldNode_1 = lambda x: SEND("80"+"31"+hencode(x, 8))
  setOldNode_2 = lambda x: SEND("80"+"32"+hencode(x, 8))
  setOldNode_3 = lambda x: SEND("80"+"33"+hencode(x, 8))
  getOldNodeHash = lambda: SEND("80"+"30")


  # Return bytes, Q for unsigned long long, < for   little-endian
  DT = struct.pack('<Q', DT)

  dt = 0

  newhash = valuehash # well... not really, will be ignored and computed on device on first run!
  oldhash = ZH # ignored..
  sig = ZH # ignored

  FRES = None


  ROOTHASH = ntrie.load()

  if ROOTHASH != device_roothash: raise Exception

  _PATH = ntrie.find_path(ROOTHASH, keyhash)

  for depth in range(64-1, -1-1, -1):
    oldnode = _PATH[depth] # int(keyhash.encode('hex')[depth], 16))

    # IS: send the node date in 3 chunks: 192 + 192 + 128 = 512 bytes, buffer = 256 bytes, thus 256 - 4bytes (prefix-> CLA + function opcode) = 252 bytes
    setOldNode_1(oldnode[:32*6])
    setOldNode_2(oldnode[32*6:32*12])
    setOldNode_3(oldnode[32*12:])

    # valuehash -> grabage value for the first insertion, it will be updated later on the way
    # newhash -> same as valuehash
    # oldhash -> initialized with ZH value (hash(32*\0x00)
    # sig -> same as oldhash
    # DT argument #4, multiplied by 10 for getting ticks (one tick/100ml)
    # RNONCE -> argument #5, user nonce
    # nbytes -> argument #3, #random_bytes to be returned,
    res = executeQueryInsert(depth, keyhash, valuehash, newhash, oldhash, sig, DT, RNONCE, nbytes)
    if depth < 0 and res.encode("hex")[:8] == "f"*8:

      FRES = res
      if newroothashhost != newhash: raise Exception
      ntrie.save(ROOTHASH)
      continue

    newhash = res[1+32+32:][:32] #IS: hash of the updated node
    oldhash = res[1+32+32+32:][:32] #IS: hash of the old node

    if depth == 63:
      _res = res[1+32+32+32+32:]
      _t0 = _res[:8]
      _dt = _res[8:][:8]
      _rnonce = _res[16:][:32]
      _nbytes = _res[48]
      _hash = _res[49:]

      valuehash = _hash

      newroothashhost = ntrie.insert(ROOTHASH, keyhash, _hash, dry=False)
      ROOTHASH  = ntrie.load()
      _NEW_PATH = ntrie.find_path(ROOTHASH, keyhash)
    if depth >= 0 and depth != 63:
      if res[-32:] != SHA256(_NEW_PATH[depth]):
        print "NEW HASH MISMATCH!!!"
        print "Host new node is.. ", _NEW_PATH[depth].encode('hex')
        raise Exception

    if oldhash != SHA256(oldnode):
      print "getOldNodeHash=", oldnodehash.encode('hex')
      print "oldNodeHash_REAL=", SHA256(oldnode).encode('hex')
      raise Exception


  FRESa=FRES[:4+32+32]
  FRESb=FRES[4+32+32:]
  rngres_ = SEND("80"+"22"+(FRESa+_t0+_dt+_rnonce+_nbytes+FRESb).encode('hex'))[1:].encode('hex')


  return rngres_[:nbytes*2]

def random_value(minval, maxval, random_cycling=False):
  """Outputs a random number between minval and maxval
  
  Arguments:
    minval {int} -- minimum value
    maxval {int} -- maximum value
  
  Keyword Arguments:
    random_cycling {bool} -- perform random cycling 
  
  Raises:
    Exception -- [description]
  """
  rngres = random_bytes()  

  # Record the sample in a file for monitoring
  with open('data.bin', 'ab') as f:
    f.write(rngres.decode('hex'))

  
  SCALING_RANGE = maxval-minval+1 #this is actualy the output range e.g. [1-6] for a dice game
  MAX_RANGE = 1<<256 #the random bytes returned are 32 (256 bits)
  limit = MAX_RANGE - (MAX_RANGE % SCALING_RANGE)

  rngres_int = long(rngres,16)

  # This is done in order to eliminate the bias introduced by the modulo operation,
  # however in our case this is highly unlikely to happen since 32 bytes of entropy
  # is generated, a really huge number and thus the probability of this to happen
  # is negligible, thus we raise an exception
  if rngres_int >= limit:
    raise Exception
  # Background cycling
  elif random_cycling and random.randint(0, 100) == 0:
    raise Exception
  else:
    return (rngres_int % SCALING_RANGE) + minval


def main():
  for x in range(1000):
    print random_bytes()

if __name__ == '__main__':
  main()