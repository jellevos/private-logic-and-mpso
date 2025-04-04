import statistics
import subprocess


compilation = subprocess.run(['cargo', 'build', '--release'], capture_output=False, text=True)
location = 'target/release/ec_mpso'

universe = 2**32
k = 256

reps = 25
precision_perc = 0.01


# We perform a binary search to find fpr where the run time is equal to the provided run times
ns = range(2, 30)
crossover_times = [
    11.64,
    22.8,
    29.4,
    41.92,
    48.0,
    60.88,
    96.76,
    104.68,
    213.0,
    332.8,
    580.52,
    1003.56,
    1376.36,
    2327.64,
    3982.88,
    4743.24,
    5524.36,
    7137.84,
    8428.96,
    9602.16,
    9447.2,
    10606.88,
    11195.32,
    12674.24,
    14300.68,
    12416.0,
    14736.12,
    15368.64,
]
crossover_times = [x / 1000. for x in crossover_times]
assert len(crossover_times) == len(ns)


def run(n: int, k: int, u: int, fpr: float, mitigation: str, reps: int) -> float:
    times = []
    for _ in range(reps):
        result = subprocess.run([location, 'bf-mitigations', str(n), str(k), str(u), str(fpr), mitigation], capture_output=True, text=True)
        assert result.returncode == 0, '\n\n'.join([result.stdout, result.stderr])
        ms = int(result.stdout.split(' ')[-2])
        times.append(ms)
    mean = statistics.mean(times)
    return mean / 1000


slack = 0.005


def experiment(mitigation: str):
    crossover_fprs = []
    highest_fpr = 0.9999999
    lowest_fpr = 0.5
    for n, t in zip(ns, crossover_times):
        # Find a lower bound for the time (we essentially just choose fpr = 1.0)
        time_lower_bound = run(n, k, universe, highest_fpr, mitigation, reps)

        # Find an upper bound for the time by starting at 0.5 (or the previous lowest_fpr) and dividing by 2 until we go over the target time
        time_upper_bound = run(n, k, universe, lowest_fpr, mitigation, reps)
        while time_upper_bound < t:
            lowest_fpr /= 2
            time_upper_bound = run(n, k, universe, lowest_fpr, mitigation, reps)
        if lowest_fpr < 2**(-200):
            crossover_fprs.append(-201)
            continue
        lowest_fpr = max(2**(-200), lowest_fpr - slack)
        time_upper_bound = run(n, k, universe, lowest_fpr, mitigation, reps)

        print('Targeting', t, 'with', lowest_fpr, '< fpr <', highest_fpr)
        print(time_lower_bound, time_upper_bound)

        if t < time_lower_bound:
            print(f"Too slow for {n}...")
            crossover_fprs.append(None)
            continue

        mean = None

        target_offset = precision_perc * t
        while mean is None or not (t - target_offset <= mean <= t + target_offset):
            between_fpr = (highest_fpr + lowest_fpr) / 2
            mean = run(n, k, universe, between_fpr, mitigation, reps)
            #print('->', between_fpr, ":", mean)
            print(f"{round(t / mean, 3)}, ", end='', flush=True)

            if mean > t:
                lowest_fpr = between_fpr - slack
            else:
                highest_fpr = between_fpr + slack

        crossover_fprs.append(between_fpr)
        highest_fpr = lowest_fpr
        print()
        print("Found", between_fpr, "for n=", n)

    print(crossover_fprs)
    return crossover_fprs



# First for mitigation = 0
a = experiment('0')
b = experiment('2')

print()
print(a)
print(b)
