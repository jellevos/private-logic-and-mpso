import statistics
import subprocess


compilation = subprocess.run(['cargo', 'build', '--release'], capture_output=True, text=True)
location = 'target/release/ec_mpso'

universe = 2**32
fpr = 2**-10

reps = 10

for n in [2, 3, 5]:
    for k in [256, 4096, 65536]:
        for mitigation in range(4):
            times = []
            for _ in range(reps):
                result = subprocess.run([location, 'bf-mitigations', str(n), str(k), str(universe), str(fpr), str(mitigation)], capture_output=True, text=True)
                assert result.returncode == 0
                ms = int(result.stdout.split(' ')[-2])
                times.append(ms)
            mean = statistics.mean(times)
            stdev = statistics.stdev(times)
            print(n, k, mitigation, 'mean', mean, 'stdev', stdev)
