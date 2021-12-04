# milli-klockstat

This tool is a modification of kLockStat by Prathyush PV. More information about kLockStat can be found [here](https://github.com/prathyushpv/klockstat) and [here](https://prathyushpv.github.io/2019/04/30/kLockStat.html).

Milli-kLockStat records aggregate information about the time spent waiting to acquire kernel locks; by default, the sampling period is 50ms (20 aggregate samples per second). For each combination of process/thread ID and lock address, the following information is captured for each sampling period:

* The timestamp of the start of the sampling period
* The number of times the thread attempted to access the lock in one period
* The sum (in ns) of time spent waiting for the lock to become accessible over the entire period

This allows the average wait time for a specific thread and lock to be derived for each period. Additionally, the following information is also provided for each thread-lock combination:

* The process ID and thread ID for the thread
* The command used to run the process
* The address of the lock
* The type of lock (mutex, semaphore, R/W)
* A stack trace of the first time the thread accessed the lock while Milli-klockstat was running (future stack traces are not captured in order to reduce logging overhead)

For more information about what Milli-kLockStat prints out and its arguments, see the comments at the start of mklockstat.py.

The provided Jupyter notebook includes several useful functions for analyzing and graphing the collected data.
## Usage
First, install the required dependencies:

`sudo apt-get install bpfcc-tools linux-headers-$(uname -r)`

Then, run mklockstat:

`sudo python3 mklockstat.py (--period 50) (--time 10) (--no-filter-monitors)`

The period argument controls the sampling period in milliseconds. By default, it is 50ms.

The time argument controls the time before the monitor automatically terminates. By default, it is 10s.

The no-filter-monitors argument will disable the automatic filtering of lock accesses by some known monitors (collect, collectl, tcplife-bpfcc)
