import sys
import hashlib
import plyvel

SHA256 = lambda x: hashlib.sha256(x).digest()
KS = plyvel.DB("keystore.db", create_if_missing=True)
EMPTY_VALUE = "\x00"*32

def ks_add(key, value):
    KS.put(key, value)

def save(roothash):
    KS.put(b'ROOTHASH', roothash)

def db_init():
    prevhash = SHA256(EMPTY_VALUE) #sha256 of 32-byte zero value
    ks_add(SHA256(EMPTY_VALUE), EMPTY_VALUE) #store it on the db
    #calculate the ROOThash: bottom-up; from leaves to root, all the nodes at the same level have the same value initially
    for _ in range(64):
        content = prevhash*16 #each node has 16 children (0-f in hex, i.e. a nibble )
        prevhash = SHA256(content) #claclulate the concatenated children
        ks_add(SHA256(content), content)

    save(prevhash) #initialize the db:ROOTHASH'
    return prevhash #f5438e0d99e0fa7d048707b2c16909b24c87df9bb5d8abf5ee6074ca9a25191a

def load():
    try:
        roothash = KS.get(b'ROOTHASH')
        if roothash is None:
            return db_init()
        return roothash
    except:
        print sys.exc_info()

def save_state(state):
    KS.put(b'STATE', state)

def get_state():
    return KS.get(b'STATE')

def get_offsets(key):
    offsets = []
    for i in key.encode('hex'):
        offsets.append(int(i, 16)) #return ints and not hex values; for indexing
    return offsets

def find_path(roothash, key):
    path = []
    offsets = get_offsets(key) #integer offsets
    nodehash = roothash #start from the roothash
    for i in offsets:
        node = KS.get(nodehash)
        path.append(node) #append the node value
        nodehash = node[32*i:][:32]
    return path

def insert(roothash, key, value, dry=False):
    offsets = get_offsets(key)
    depth = 63
    lasthash = value
    for oldnode in find_path(roothash, key)[::-1]:
        offset = offsets[depth]
        newnode = oldnode[:offset*32] + lasthash + oldnode[(offset+1)*32:] #update the node with the new hash
        ks_add(SHA256(newnode), newnode) #add the new value to the database
        lasthash = SHA256(newnode) #calculate the hash of the newly updated node, to be inserte
        depth -= 1
    if not dry:
        save(lasthash)
    return lasthash
