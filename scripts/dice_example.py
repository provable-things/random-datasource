import rng
from progress.bar import Bar

nsamples = 4096
bar = Bar('Rolling the dice', max=nsamples, suffix='%(index)d/%(max)d - %(percent).1f%% - %(eta)ds')

for i in range(0, nsamples):
  bar.next()
  rng.random_value(1, 6)
