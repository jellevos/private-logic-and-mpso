import statistics
import subprocess


compilation = subprocess.run(['cargo', 'build', '--release'], capture_output=False, text=True)
location = 'target/release/ec_mpso'

universe = 2**32
k = 256

reps = 20
precision = 0.0001


# We perform a binary search to find fpr where the run time is equal to the provided run times
ns = range(2, 51)
crossover_times = [0.05 * n for n in ns]


def run(n: int, k: int, u: int, fpr: float, mitigation: int, reps: int) -> float:
    times = []
    for _ in range(reps):
        result = subprocess.run([location, 'bf-mitigations', str(n), str(k), str(u), str(fpr), str(mitigation)], capture_output=True, text=True)
        assert result.returncode == 0
        ms = int(result.stdout.split(' ')[-2])
        times.append(ms)
    mean = statistics.mean(times)
    return mean / 1000


slack = 0.01

# First for mitigation = 0
crossover_fprs = []
highest_fpr = 0.999
lowest_fpr = 0.5
for n, t in zip(ns, crossover_times):
    # Find a lower bound for the time (we essentially just choose fpr = 1.0)
    time_lower_bound = run(n, k, universe, highest_fpr, 0, reps)

    # Find an upper bound for the time by starting at 0.5 (or the previous lowest_fpr) and dividing by 2 until we go over the target time
    time_upper_bound = run(n, k, universe, lowest_fpr, 0, reps)
    while time_upper_bound < t:
        lowest_fpr /= 2
        time_upper_bound = run(n, k, universe, lowest_fpr, 0, reps)
    lowest_fpr -= slack
    time_upper_bound = run(n, k, universe, lowest_fpr, 0, reps)

    print('Targeting', t, 'with', lowest_fpr, '< fpr <', highest_fpr)
    print(time_lower_bound, time_upper_bound)
    assert time_lower_bound < t < time_upper_bound

    mean = None

    while mean is None or not (t - precision <= mean <= t + precision):
        between_fpr = (highest_fpr + lowest_fpr) / 2
        mean = run(n, k, universe, between_fpr, 0, reps)
        print('->', between_fpr, ":", mean)

        if mean > t:
            lowest_fpr = between_fpr - slack
        else:
            highest_fpr = between_fpr + slack

    crossover_fprs.append(between_fpr)
    highest_fpr = lowest_fpr
    print("Found", between_fpr, "for n=", n)
