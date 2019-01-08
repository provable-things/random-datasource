 #!/usr/bin/env python

import os
import logging
import datetime
import shutil
import numpy as np

from progress.bar import Bar

class Monitor():
  SAMPLE_SIZE = 256 * 16
  CHI_SQUARE_SUM_LIMIT = 330.5197 * 16

  def __init__(self):
    self.counter = 0
    self.data = np.zeros((256, 32), np.uint8)
    FORMAT = '%(asctime)-15s - %(message)'
    logging.basicConfig(filename='logging.log', level=logging.DEBUG)

  # Process a 32 bytes integer
  # in 32 groups of one byte each
  def add(self, n):
    if self.counter == self.SAMPLE_SIZE:
      logging.info('adding no more samples')
      return
    # Split in groups of 8-bit, so
    # 256 possible values
    logging.info('Adding sample: %d' % n)
    for i in range(0, 32):
      value = n >> (i * 8) & 0xFF
      self.data[value, i] += 1
      logging.debug('value = %d' % value)
      logging.debug('Row modified')
      logging.debug(self.data[value, :].T)

    self.counter += 1

  def store(self, file, n):
    f.write(n)
    logging.debug('%s stored' % n)

  # Deprecated
  def load(self, file, i):
    with open(file, 'r') as f:
      c = f.read()
      value = c[i:i+32]
      logging.debug('%s loaded' % value.encode('hex'))
      return value

  # Performs a chi-square test on 
  # the samples collected
  def chi_square(self):
    if(self.counter == self.SAMPLE_SIZE):
      logging.info('Performing chi-square test')
      exp = np.ones(32) * (self.SAMPLE_SIZE / 256)

      # Produce a chi-squared value for each group
      sum = np.power(np.sum(self.data, axis=0) - exp, 2) / exp

      logging.debug('current sum')
      logging.debug(sum)
      logging.debug(sum > self.CHI_SQUARE_SUM_LIMIT)

      return np.all(sum > self.CHI_SQUARE_SUM_LIMIT)

  def show(self):
    for r in range(0, self.data.shape[0]):
      print(self.data[r,:])

    print(self.counter)
    print("")

# Use this only for testing
def write_random_samples(filename, n_samples):
  bar = Bar('Writing random samples', max=n_samples, suffix='%(index)d/%(max)d - %(percent).1f%% - %(eta)ds')
  with open(filename, 'wb') as f:
    for i in range(0, n_samples):
      #f.write(os.urandom(32)) # Test a success
      f.write("{:064x}".format(10).decode('hex')) # Test a Failure
      bar.next()


def main():
  print("Ledger monitoring")

  # Returns if the ledger is broken
  if os.path.isfile("ledger_rng_behaving_unexpectedly"):
    logging.error("Unexpected ledger behaviour.")
    return    

  filename = 'data.bin'
  failures_dir = 'failures'
  success_dir = 'successes'
  MAXFAILURES = 4
  n_samples = 4096

  # Only for testing the chi-square
  write_random_samples(filename, n_samples)

  with open(filename, 'rb') as f:
    g = f.read()
    if (len(g) < 131072):
        print('Samples limit not reach yet.')
        return
    else:
      m = Monitor()
      bar = Bar('Adding to monitor', max=n_samples, suffix='%(index)d/%(max)d - %(percent).1f%% - %(eta)ds')

      for i in range(0, n_samples):
        bar.next()
        m.add(int(g[i:i+32].encode('hex'), 16))

      # m.show()

      if (m.chi_square()):
        print("chi-square test: Success")

        if os.path.isdir(failures_dir):
          shutil.rmtree(failures_dir)

        # Rename data.bin to another file
        if not os.path.isdir(success_dir):
          os.mkdir(success_dir)
        filename = datetime.datetime.now().isoformat().replace(':', '-').split('.')[0]
        shutil.move('data.bin', '%s/%s.bin' % (success_dir, filename))

      else:
        print("chi-square test: Failure")

        if not os.path.isdir(failures_dir):
          os.mkdir(failures_dir)
        filename = datetime.datetime.now().isoformat().replace(':', '-').split('.')[0]
        shutil.move('data.bin', '%s/%s.bin' % (failures_dir, filename))

        if len(os.listdir(failures_dir)) >= MAXFAILURES:
          print("ALERT: CHI-SQUARE TEST FAILURES EXCEEDED")

          # This file is used to report a broken behaviour of the ledger
          # and deactivates it's use
          with open("ledger_rng_behaving_unexpectedly", "wb") as f:
            f.write("f")




if __name__=="__main__":
  main()
