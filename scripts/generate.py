import rng 

for i in range(1000):
    v = rng.random_bytes()

    with open('random_bytes.dat', 'a') as f:
        f.write(v)
        f.write('\n')



