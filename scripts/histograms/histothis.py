import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib.path as path

import plotly.plotly as py
import plotly.tools as tls

from Crypto.Hash import keccak

fig, ax = plt.subplots()

def keccak256(arg):
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(arg)
    return keccak_hash.hexdigest()

def main():
    data = []
    with open('random_bytes.dat', 'r') as f:
        data = f.readlines()

    data = [ x.strip() for x in data ]

    processed = []
    for sample in data:
        print sample[:14]
        value = int(keccak256(sample[:14]), 16)
        processed.append(int( value % 100 + 1 ))

    print processed

    n, bins = np.histogram(processed, xrange(1, 101))

    n = n * 1.0 / len(processed)

    # get the corners of the rectangles for the histogram
    left = np.array(bins[:-1])
    right = np.array(bins[1:])
    bottom = np.zeros(len(left))
    top = bottom + n


    # we need a (numrects x numsides x 2) numpy array for the path helper
    # function to build a compound path
    XY = np.array([[left, left, right, right], [bottom, top, top, bottom]]).T

    # get the Path object
    barpath = path.Path.make_compound_path_from_polys(XY)

    # make a patch out of it
    patch = patches.PathPatch(barpath)
    ax.add_patch(patch)

    # update the view limits
    ax.set_xlim(left[0], right[-1])
    ax.set_ylim(bottom.min(), top.max())

    plt.show()


if __name__ == '__main__':
    main()

