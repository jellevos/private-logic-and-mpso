import statistics
import subprocess


compilation = subprocess.run(['cargo', 'build', '--release'], capture_output=False, text=True)
location = 'target/release/ec_mpso'

universe = 2**32

reps = 25


# We perform a binary search to find fpr where the run time is equal to the provided run times
ns = range(2, 43)
crossover_times_256 = [
    {
    2: 9.81,  # errors: 0, median: 8.0, std: 6.069787741949733, min: 7.0, max: 46.0
3: 21.15,  # errors: 0, median: 17.0, std: 12.629430915624237, min: 14.0, max: 89.0
4: 28.85,  # errors: 0, median: 23.0, std: 15.368454507184317, min: 16.0, max: 90.0
5: 34.69,  # errors: 0, median: 30.0, std: 12.656850263231314, min: 22.0, max: 82.0
6: 48.45,  # errors: 0, median: 43.0, std: 17.49307222181329, min: 29.0, max: 103.0
7: 61.64,  # errors: 0, median: 53.5, std: 20.37800358972955, min: 37.0, max: 130.0
8: 89.71,  # errors: 0, median: 76.0, std: 39.05326458501869, min: 44.0, max: 304.0
9: 132.02,  # errors: 0, median: 111.0, std: 91.41734468409652, min: 49.0, max: 590.0
10: 181.77,  # errors: 0, median: 123.0, std: 148.3676742679374, min: 63.0, max: 1105.0
11: 320.06,  # errors: 0, median: 195.5, std: 327.74179353924825, min: 73.0, max: 2132.0
12: 478.97,  # errors: 0, median: 329.5, std: 413.2106722931654, min: 101.0, max: 2138.0
13: 1059.06,  # errors: 0, median: 601.0, std: 968.1675894245382, min: 110.0, max: 4121.0
14: 1559.93,  # errors: 0, median: 1137.5, std: 1213.0886054808507, min: 207.0, max: 5116.0
15: 2221.95,  # errors: 0, median: 2122.5, std: 1547.9771967038635, min: 139.0, max: 6172.0
16: 3697.45,  # errors: 0, median: 4135.5, std: 1904.6983343693812, min: 233.0, max: 7161.0
17: 4345.45,  # errors: 0, median: 4669.5, std: 2026.63014508062, min: 376.0, max: 7189.0
18: 5639.5,  # errors: 0, median: 6151.0, std: 1722.6374393570886, min: 641.0, max: 9159.0
19: 6633.83,  # errors: 0, median: 6189.5, std: 1901.8547621899645, min: 1154.0, max: 10221.0
20: 7617.21,  # errors: 0, median: 8173.0, std: 2035.6868262197022, min: 1192.0, max: 11198.0
21: 8656.59595959596,  # errors: 1, median: 9201.0, std: 2162.9064342335328, min: 2199.0, max: 12227.0
22: 9648.340206185567,  # errors: 3, median: 10191.0, std: 2043.0232137213036, min: 3193.0, max: 13246.0
23: 10971.255102040815,  # errors: 2, median: 11221.0, std: 1692.891209024448, min: 6217.0, max: 14255.0
24: 12263.074468085106,  # errors: 6, median: 12251.5, std: 1760.6764904639053, min: 7240.0, max: 15274.0
25: 13162.3125,  # errors: 4, median: 13255.0, std: 1739.5217268427245, min: 8248.0, max: 16260.0
26: 13938.977777777778,  # errors: 10, median: 14289.5, std: 2022.0731100585785, min: 9256.0, max: 17263.0
27: 14989.752808988764,  # errors: 11, median: 15299.0, std: 1863.1330179962197, min: 8348.0, max: 18294.0
28: 15827.852272727272,  # errors: 12, median: 16281.5, std: 1910.7567528941008, min: 10278.0, max: 19588.0
29: 17383.885057471263,  # errors: 13, median: 17357.0, std: 1813.7510304857385, min: 14313.0, max: 20904.0
30: 18403.989247311827,  # errors: 7, median: 18412.0, std: 1944.1738073951576, min: 13116.0, max: 21565.0
31: 19640.050632911392,  # errors: 21, median: 19567.0, std: 1879.0740415996643, min: 14333.0, max: 22658.0
32: 20409.119047619046,  # errors: 16, median: 20394.0, std: 1862.5413032034594, min: 15388.0, max: 25465.0
33: 21064.97701149425,  # errors: 13, median: 21430.0, std: 2298.3376650790888, min: 14449.0, max: 24855.0
34: 22811.739726027397,  # errors: 27, median: 23407.0, std: 2357.4875104382095, min: 16771.0, max: 27465.0
35: 23669.52564102564,  # errors: 22, median: 23868.5, std: 2315.6719746413123, min: 17454.0, max: 28792.0
36: 24928.91139240506,  # errors: 21, median: 24870.0, std: 2350.5141401015367, min: 17953.0, max: 30635.0
37: 26661.085365853658,  # errors: 18, median: 26642.5, std: 2736.5760042780844, min: 19463.0, max: 34175.0
38: 27689.951807228917,  # errors: 17, median: 27720.0, std: 2639.461086456367, min: 19607.0, max: 34750.0
39: 29367.177215189873,  # errors: 21, median: 29299.0, std: 3100.213796430298, min: 21794.0, max: 40571.0
40: 32077.963414634145,  # errors: 18, median: 31353.5, std: 3943.992441848873, min: 21647.0, max: 44225.0
41: 33728.666666666664,  # errors: 19, median: 33350.0, std: 3587.3434460614444, min: 27931.0, max: 45340.0
42: 37331.45238095238,  # errors: 16, median: 35350.0, std: 6725.319737827961, min: 29612.0, max: 80877.0
    }[n] for n in range(2, 43)
]
crossover_times_256 = [x / 1000. for x in crossover_times_256]
assert len(crossover_times_256) == len(ns)

crossover_times_128 = [
    {
2: 8.48,  # errors: 0, median: 8.0, std: 2.238302928559939, min: 7.0, max: 18.0
3: 16.64,  # errors: 0, median: 16.0, std: 2.079262689833426, min: 13.0, max: 23.0
4: 21.84,  # errors: 0, median: 21.0, std: 4.170131892398609, min: 17.0, max: 34.0
5: 28.56,  # errors: 0, median: 27.0, std: 4.144072071445348, min: 23.0, max: 37.0
6: 41.52,  # errors: 0, median: 38.0, std: 10.476640682967036, min: 30.0, max: 72.0
7: 50.96,  # errors: 0, median: 50.0, std: 9.58070978581441, min: 36.0, max: 68.0
8: 89.08,  # errors: 0, median: 73.0, std: 44.91094892488171, min: 52.0, max: 180.0
9: 109.08,  # errors: 0, median: 81.0, std: 62.57257120069997, min: 58.0, max: 330.0
10: 138.24,  # errors: 0, median: 94.0, std: 78.34447438503028, min: 68.0, max: 317.0
11: 250.76,  # errors: 0, median: 133.0, std: 222.80546073499485, min: 80.0, max: 1091.0
12: 681.56,  # errors: 0, median: 576.0, std: 746.0518346603003, min: 86.0, max: 3098.0
13: 708.48,  # errors: 0, median: 590.0, std: 718.2686428721034, min: 96.0, max: 3113.0
14: 1565.92,  # errors: 0, median: 1118.0, std: 1123.4413988573976, min: 223.0, max: 4116.0
15: 2277.375,  # errors: 1, median: 2126.0, std: 1400.218144883457, min: 351.0, max: 5129.0
16: 3174.32,  # errors: 0, median: 3134.0, std: 1806.8922841903627, min: 617.0, max: 7146.0
17: 4896.76,  # errors: 0, median: 5154.0, std: 2128.1435822487792, min: 376.0, max: 7158.0
18: 4683.739130434783,  # errors: 2, median: 4170.0, std: 2063.049006102625, min: 1153.0, max: 8161.0
19: 5301.291666666667,  # errors: 1, median: 5176.5, std: 1964.4674127049575, min: 1173.0, max: 9185.0
20: 7506.772727272727,  # errors: 3, median: 8184.0, std: 1730.0626449384008, min: 5180.0, max: 10199.0
21: 8686.36,  # errors: 0, median: 9192.0, std: 1849.4083711645012, min: 4214.0, max: 12215.0
22: 9698.368421052632,  # errors: 6, median: 10230.0, std: 2009.3979255965735, min: 4225.0, max: 13216.0
23: 10552.478260869566,  # errors: 2, median: 11225.0, std: 2100.09573092547, min: 6261.0, max: 14249.0
24: 12322.8,  # errors: 5, median: 12258.5, std: 1822.044704518294, min: 10246.0, max: 15274.0
25: 12976.863636363636,  # errors: 3, median: 13301.5, std: 1758.407729289269, min: 9293.0, max: 15298.0
26: 13444.6,  # errors: 5, median: 13343.0, std: 1865.6122573398907, min: 9315.0, max: 17377.0
27: 14181.59090909091,  # errors: 3, median: 14410.0, std: 2267.8256769129766, min: 9352.0, max: 18345.0
28: 16151.42857142857,  # errors: 4, median: 17340.0, std: 2405.207508125413, min: 9614.0, max: 19538.0
29: 17352.91304347826,  # errors: 2, median: 17542.0, std: 2247.586036639056, min: 11794.0, max: 20716.0
30: 18624.095238095237,  # errors: 4, median: 18446.0, std: 1651.2014384914369, min: 15522.0, max: 21463.0
31: 18844.684210526317,  # errors: 6, median: 19512.0, std: 2389.447938393385, min: 14451.0, max: 21678.0
32: 20492.95,  # errors: 5, median: 21079.5, std: 1836.3859093052138, min: 16485.0, max: 22722.0
33: 21170.25,  # errors: 1, median: 20748.5, std: 1910.967140754513, min: 17548.0, max: 25106.0
34: 23232.68181818182,  # errors: 3, median: 23170.5, std: 1980.3322084549743, min: 18943.0, max: 27333.0
35: 23242.52380952381,  # errors: 4, median: 23018.0, std: 2750.3907834896413, min: 16015.0, max: 28152.0
36: 25947.18181818182,  # errors: 3, median: 26528.5, std: 2170.561407219529, min: 20650.0, max: 29908.0
37: 27504.052631578947,  # errors: 6, median: 27072.0, std: 3314.8685154699274, min: 21657.0, max: 33764.0
38: 29154.75,  # errors: 9, median: 28826.0, std: 2076.590426636895, min: 25751.0, max: 34083.0
39: 31465.105263157893,  # errors: 6, median: 31201.0, std: 2337.543817646036, min: 28206.0, max: 35853.0
40: 33623.1,  # errors: 5, median: 32582.5, std: 5271.403427431526, min: 26067.0, max: 45085.0
41: 34187.45,  # errors: 5, median: 33957.0, std: 3299.528299222242, min: 27872.0, max: 40068.0
42: 38721.57142857143,  # errors: 4, median: 37801.0, std: 5771.792222277484, min: 27757.0, max: 50423.0
# 43: 41865.47368421053,  # errors: 6, median: 39587.0, std: 5909.141847533278, min: 34781.0, max: 52843.0
# 44: 46234.75,  # errors: 5, median: 48321.0, std: 7285.207246085801, min: 35357.0, max: 65541.0
# 45: 49896.78947368421,  # errors: 6, median: 48078.0, std: 8216.458317702933, min: 37153.0, max: 68503.0
# 46: 55712.086956521736,  # errors: 2, median: 49360.0, std: 14540.879077818205, min: 38831.0, max: 90838.0
# 47: 65547.52380952382,  # errors: 4, median: 61068.0, std: 16087.188538147515, min: 45221.0, max: 111154.0
# 48: 72480.88235294117,  # errors: 8, median: 67943.0, std: 22497.40529450661, min: 46641.0, max: 124939.0
# 49: 82137.5,  # errors: 1, median: 76881.5, std: 30169.40009058992, min: 43352.0, max: 168984.0
    }[n] for n in range(2, 43)
]
crossover_times_128 = [x / 1000. for x in crossover_times_128]
assert len(crossover_times_128) == len(ns)

crossover_times_512 = [
    {
2: 17.52,  # errors: 0, median: 9.0, std: 41.98325062847484, min: 8.0, max: 219.0
3: 18.64,  # errors: 0, median: 18.0, std: 2.4474476501040834, min: 16.0, max: 25.0
4: 22.48,  # errors: 0, median: 22.0, std: 2.7098585448936876, min: 19.0, max: 29.0
5: 30.4,  # errors: 0, median: 30.0, std: 4.425306015783918, min: 25.0, max: 41.0
6: 38.08,  # errors: 0, median: 38.0, std: 4.8727131388307, min: 31.0, max: 48.0
7: 57.04,  # errors: 0, median: 52.0, std: 19.53944727979786, min: 39.0, max: 108.0
8: 84.0,  # errors: 0, median: 73.0, std: 52.8504178476071, min: 46.0, max: 299.0
9: 121.0,  # errors: 0, median: 82.0, std: 105.72763750946739, min: 58.0, max: 557.0
10: 125.44,  # errors: 0, median: 121.0, std: 44.97043473216598, min: 63.0, max: 191.0
11: 230.72,  # errors: 0, median: 194.0, std: 143.38599420213026, min: 78.0, max: 578.0
12: 456.76,  # errors: 0, median: 331.0, std: 329.9592500092499, min: 107.0, max: 1103.0
13: 1091.6,  # errors: 0, median: 1100.0, std: 822.0781593011701, min: 149.0, max: 3108.0
14: 1707.96,  # errors: 0, median: 2112.0, std: 1435.693255306764, min: 151.0, max: 5338.0
15: 2524.72,  # errors: 0, median: 2128.0, std: 1517.418024144962, min: 612.0, max: 5130.0
16: 3686.64,  # errors: 0, median: 3140.0, std: 1931.4449659948032, min: 376.0, max: 7145.0
17: 4260.92,  # errors: 0, median: 5149.0, std: 2086.6616064901373, min: 381.0, max: 7154.0
18: 5103.88,  # errors: 0, median: 5152.0, std: 2094.5932047376964, min: 651.0, max: 8170.0
19: 6430.4,  # errors: 0, median: 6181.0, std: 1866.6074841808602, min: 2182.0, max: 9187.0
20: 8046.96,  # errors: 0, median: 8196.0, std: 2099.9401674016017, min: 3192.0, max: 11206.0
21: 8775.12,  # errors: 0, median: 9204.0, std: 1959.9152047984117, min: 5215.0, max: 12211.0
22: 9880.12,  # errors: 0, median: 9249.0, std: 2342.0886212951036, min: 5223.0, max: 13256.0
23: 10577.64,  # errors: 0, median: 10250.0, std: 2069.547854806294, min: 5351.0, max: 13287.0
24: 11722.08,  # errors: 0, median: 12266.0, std: 1919.1199137451868, min: 6288.0, max: 14286.0
25: 13278.24,  # errors: 0, median: 13299.0, std: 1652.0680040482596, min: 10292.0, max: 15430.0
26: 14049.68,  # errors: 0, median: 13456.0, std: 2046.6866866556136, min: 9304.0, max: 17322.0
27: 15523.36,  # errors: 0, median: 15369.0, std: 1731.187234241288, min: 10366.0, max: 18342.0
28: 17126.16,  # errors: 0, median: 17394.0, std: 1745.1768458621416, min: 14331.0, max: 19570.0
29: 16734.36,  # errors: 0, median: 16442.0, std: 2306.129836616606, min: 11507.0, max: 20463.0
30: 17987.32,  # errors: 0, median: 17867.0, std: 2563.7567279287637, min: 12427.0, max: 21624.0
31: 19397.32,  # errors: 0, median: 19455.0, std: 1611.9584547996267, min: 16524.0, max: 22451.0
32: 20487.76,  # errors: 0, median: 20668.0, std: 2033.8404206492373, min: 15605.0, max: 23482.0
33: 21396.68,  # errors: 0, median: 20927.0, std: 1842.8882612175198, min: 17874.0, max: 24690.0
34: 22146.92,  # errors: 0, median: 21984.0, std: 1810.939970475738, min: 18793.0, max: 24892.0
35: 23545.08,  # errors: 0, median: 24082.0, std: 2334.8461926502423, min: 15682.0, max: 26505.0
36: 26160.24,  # errors: 0, median: 25852.0, std: 1958.8131032166732, min: 21212.0, max: 30678.0
37: 26134.958333333332,  # errors: 1, median: 25829.5, std: 2222.402508825052, min: 21091.0, max: 30320.0
38: 28350.44,  # errors: 0, median: 28495.0, std: 2654.552647183074, min: 20586.0, max: 32966.0
39: 30130.958333333332,  # errors: 1, median: 30971.0, std: 3032.0237821593205, min: 23381.0, max: 35387.0
40: 32959.681818181816,  # errors: 3, median: 32846.5, std: 2547.910617150259, min: 27806.0, max: 38037.0
41: 35843.608695652176,  # errors: 2, median: 33852.0, std: 4976.831145318461, min: 29002.0, max: 48174.0
42: 37065.545454545456,  # errors: 3, median: 35746.0, std: 6050.963533877203, min: 29129.0, max: 55894.0
# 43: 40229.59090909091  # errors: 3, median: 39796.0, std: 5397.6589692648095, min: 31518.0, max: 54069.0
# 44: 47367.28571428572  # errors: 4, median: 44061.0, std: 11592.82663608344, min: 35132.0, max: 84962.0
# 45: 48268.217391304344  # errors: 2, median: 47986.0, std: 8371.787188128957, min: 34681.0, max: 65781.0
# 46: 52528.954545454544  # errors: 3, median: 52113.0, std: 10674.911497245585, min: 38497.0, max: 74751.0
# 47: 58846.04761904762  # errors: 4, median: 55637.0, std: 13711.517652966759, min: 43929.0, max: 92488.0
# 48: 60849.217391304344  # errors: 2, median: 57081.0, std: 17034.00477375802, min: 42493.0, max: 113682.0
# 49: 77701.95238095238  # errors: 4, median: 63791.0, std: 31148.49764350793, min: 40302.0, max: 167637.0
    }[n] for n in range(2, 43)
]
crossover_times_512 = [x / 1000. for x in crossover_times_512]
assert len(crossover_times_512) == len(ns)


def run(n: int, k: int, u: int, fpr: float, mitigation: str, reps: int) -> float:
    times = []
    for _ in range(reps):
        result = subprocess.run([location, 'bf-mitigations', str(n), str(k), str(u), str(fpr), mitigation], capture_output=True, text=True)
        assert result.returncode == 0, '\n\n'.join([result.stdout, result.stderr])
        ms = int(result.stdout.split(' ')[-2])
        times.append(ms)
    mean = statistics.mean(times)
    return mean / 1000


def experiment(mitigation: str, k: int, crossover_times):
    crossover_fprs = []
    fpr_pow = -1
    stop = False
    for n, t in zip(ns, crossover_times):
        mean = run(n, k, universe, 2**fpr_pow, mitigation, reps)
        while mean > t:
            if fpr_pow == -1:
                print(f"Too slow for {n}...")
                crossover_fprs.append(None)
                stop = True
                break
            print("-", end="", flush=True)
            fpr_pow += 1
            mean = run(n, k, universe, 2**fpr_pow, mitigation, reps)

        if stop:
            stop = False
            continue
            
        while mean < t:
            print("+", end="", flush=True)
            fpr_pow -= 1
            mean = run(n, k, universe, 2**fpr_pow, mitigation, reps)

        fpr_pow += 1
        crossover_fprs.append(fpr_pow)
        print("Found", fpr_pow, "for n=", n, "with previous mean", mean, ">", t)

    print(crossover_fprs)
    return crossover_fprs


# First for mitigation = 0
small_0 = experiment('0', 128, crossover_times_128)
small_1 = experiment('1', 128, crossover_times_128)
small_2 = experiment('2', 128, crossover_times_128)
small_3 = experiment('3', 128, crossover_times_128)
print()
print(small_0)
print(small_1)
print(small_2)
print(small_3)

large_0 = experiment('0', 512, crossover_times_512)
large_1 = experiment('1', 512, crossover_times_512)
large_2 = experiment('2', 512, crossover_times_512)
large_3 = experiment('3', 512, crossover_times_512)
print()
print(large_0)
print(large_1)
print(large_2)
print(large_3)


print()
print(small_0)
print(small_1)
print(small_2)
print(small_3)
print(large_0)
print(large_1)
print(large_2)
print(large_3)
