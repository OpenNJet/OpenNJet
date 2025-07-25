# Benchmark MariaDB Connector/C

This permits to benchmark MariaDB C connector, along with MySQL connector

## Installation
To install google benchmark, mysql connector and build current connector :
```script
  sudo benchmark/build.sh
  cd benchmark
  sudo ./installation.sh
```

## Basic run

This will runs the benchmark with 50 repetition to ensure stability then display results
```script
sudo ./launch.sh
```

## detailed benchmark

first ensure running cpu to maximum speed:
```script
sudo cpupower frequency-set --governor performance || true
```

default is benchmarking on one thread. adding benchmark on multiple thread can be done setting MAX_THREAD in main-benchmark.cc. Setting it to 256, benchmark will run on 1 to 256 threads.

Set server default environment with the following variables : 
* TEST_DB_PORT (default 3306)
* TEST_DB_DATABASE (default "bench")
* TEST_DB_USER (default "root")
* TEST_DB_HOST (default "localhost")
* TEST_DB_PASSWORD
* 
running with MariaDB driver:
```script
g++ main-benchmark.cc -std=c++11 -isystem benchmark/include -Lbenchmark/build/src -I/usr/local/include/mariadb -I/usr/local/include/mariadb/mysql -L/usr/local/lib/mariadb/ -lmariadb -lbenchmark -lpthread -o main-benchmark
./main-benchmark --benchmark_repetitions=10 --benchmark_time_unit=us --benchmark_min_warmup_time=10 --benchmark_counters_tabular=true --benchmark_format=json --benchmark_out=mariadb.json
```

running with MySQL driver:
```script
g++ main-benchmark.cc -std=c++11 -isystem benchmark/include -Lbenchmark/build/src -lbenchmark -lpthread -DBENCHMARK_MYSQL -lmysqlclient -o main-benchmark
./main-benchmark --benchmark_repetitions=10 --benchmark_time_unit=us --benchmark_min_warmup_time=10 --benchmark_counters_tabular=true --benchmark_format=json --benchmark_out=mysql.json
```

in order to compare results:

```script
pip3 install -r benchmark/requirements.txt
benchmark/tools/compare.py -a --no-utest benchmarksfiltered ./mysql.json MySQL ./mariadb.json MariaDB
```
