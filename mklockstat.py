# The following program is an extension of kLockStat by prathyushpv.
# The original program can be found at https://github.com/prathyushpv/klockstat.

# This modification of kLockStat has three arguments: --time (amount of seconds to run for, defaults to 10) and --period (amount of milliseconds for each period, defaults to 50).
# There is also the --no-filter-monitors argument, which if added will allow the locks used by known monitors (i.e. collectl and tcplife-bpfcc) to be logged.
# During each sampling period, this program records the number of accesses and the sum total of all lock waiting times for each combination of lock and thread.
# This data can be used to derive the average lock waiting time for each sampling period, allowing for the detection of periods of time where locks are under heavy contention.
# Some other useful data is recorded, like program names and stack traces; see the message formats below for more info.

# This program prints two types of messages to stdout:

# Sample Message
# Format: s,command,Pxxx_Tyyy,typename,lockaddr,starttime,diffsum,lockcount,stackid
# s is literally the character s, and is used to easily identify samples.
# command is the command used to run the traced program, which is typically the program name.
# Pxxx_Tyyy is the process and thread ID associated with the sample.
# typename is the type of the lock: either RWLock, Mutex, or Semaphore.
# lockaddr is the address of the lock in hex.
# starttime is the timestamp of the sample.
# diffsum is the sum of all lock waiting times in ns.
# lockcount is the number of accesses by the listed thread to the listed lock.
# stackid is an index which can be used to recover the stacktrace of the first time the listed thread accessed the listed lock. (Future stack traces are not recorded.)

# Stacktrace Message
# Format: t,stackid,trace1,trace2,...
# t is literally the character t, and is used to easily identify stack traces.
# stackid is the id of the stack trace, which is also a part of the above sample messages.
# The remaining strings gives the trace as a comma-separated list.

from bcc import BPF
import errno
import os
import time
import argparse
import sys

# Data structures holding identifiers and function names for each type of lock.
locks = [
    {'id': 1, 'name': 'write_lock', 'lock_func': '_raw_write_lock'},
    {'id': 2, 'name': 'read_lock', 'lock_func': '_raw_read_lock'},
    {'id': 3, 'name': 'mutex', 'lock_func': 'mutex_lock'},
    {'id': 4, 'name': 'write_sema', 'lock_func': 'up_write'},
    {'id': 5, 'name': 'read_sema', 'lock_func': 'up_read'}
]
lock_type_to_title = {1:"RWLock", 2: "RWLock", 3:"Mutex", 4:"Semaphore", 5:"Semaphore"}

# The header of the BPF program, defining the data structures needed to track lock wait times.
prog_header = """
#include <linux/sched.h>
#include <linux/spinlock_types.h>

// define struct for key
struct key_t {
    u64 pid_tgid;
    raw_spinlock_t* lock;
};

// define output data structure in C
struct data_t {
    u64 pid_tgid; // The process and thread IDs.
    u64 lock_address; // The address of the lock.
    u64 start_time; // The start time of the current sample. If the current timestamp exceeds this plus the sampling period, send a report.
    u64 last_start_time; // The start time of the previous sample. This is what the Python script reads.
    u64 enter_time; // The time the lock was last entered.
    u64 diff_sum; // The current accumulation of differences during a sampling period.
    u64 last_diff_sum; // The last difference accumulated during a sampling period. This is what the Python script reads.
    u64 stack_id; // An ID that can be used to obtain the stack trace for a lock.
    u32 lock_count; // The current number of locks during a sampling period.
    u32 last_lock_count; // The last lock count accumulated during a sampling period. This is what the Python script reads.
    char comm[TASK_COMM_LEN]; // The command string of the locking program.
    u8 type; // The type of the lock.
};

BPF_STACK_TRACE(stack_traces, 102400);

"""

# A pair of functions that are customized to run for each type of lock defined above.
# The first function runs when a thread tries to acquire a lock and records the time the lock was entered.
# The second function runs when the thread successfully acquires the lock and calculates the wait time.
lock_func = """
BPF_PERF_OUTPUT(_NAME_);
BPF_HASH(map__NAME_, struct key_t, struct data_t, 102400);

int lock__NAME_(struct pt_regs *ctx, raw_spinlock_t *lock) {

    u32 current_pid = bpf_get_current_pid_tgid();
    if(current_pid == CUR_PID)
        return 0;
        
    struct data_t data = {};
    struct key_t key = {bpf_get_current_pid_tgid(), lock};
    struct data_t *data_ptr;
    data_ptr = map__NAME_.lookup(&key);
    if(data_ptr)
    {
        data_ptr->enter_time = bpf_ktime_get_ns();
        data_ptr->lock_count += 1;
    }
    else
    {
        data.pid_tgid = bpf_get_current_pid_tgid();
        data.enter_time = bpf_ktime_get_ns();
        data.start_time = data.enter_time - data.enter_time % _PERIOD_000000;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.lock_address = (u64)lock;
        data.lock_count = 1;
        data.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
        data.type = _ID_;
        map__NAME_.insert(&key, &data);
    }
    return 0;
}

int release__NAME_(struct pt_regs *ctx, raw_spinlock_t *lock) {
    u64 present = bpf_ktime_get_ns();
    
    u32 current_pid = bpf_get_current_pid_tgid();
    if(current_pid == CUR_PID)
        return 0;
        
    struct data_t *data;
    struct key_t key = {bpf_get_current_pid_tgid(), lock};
    data = map__NAME_.lookup(&key);
    if(data)
    {
        data->diff_sum += (present - data->enter_time);
        if(data->start_time + _PERIOD_000000 < present)
        {
            data->last_start_time = data->start_time;
            data->start_time = present - present % _PERIOD_000000;
            data->last_diff_sum = data->diff_sum;
            data->diff_sum = 0;
            data->last_lock_count = data->lock_count;
            data->lock_count = 0;
            _NAME_.perf_submit(ctx, data, sizeof(struct data_t));
        }
    }
    return 0;
}
"""

# Data structure to hold data about lock accesses during a sample period for a specific lock and thread.
class Sample:
    def __init__(self, pid_tgid: int, lock_address: int, start_time: int, diff_sum: int, lock_count: int, comm: str, type: int, stackid: int):
        self.pid_tgid = pid_tgid
        self.lock_address = lock_address
        self.start_time = start_time
        self.diff_sum = diff_sum
        self.lock_count = lock_count
        self.comm = comm.decode("ascii")
        self.type = type
        self.stackid = stackid
        
    def print(self):
        pid = self.pid_tgid & 0xFFFFFFFF
        tid = self.pid_tgid >> 32
        type_name = lock_type_to_title[self.type]
        print(f"s,{self.comm},P{pid}_T{tid},{type_name},{format(self.lock_address, '#04x')},{self.start_time},{self.diff_sum},{self.lock_count},{self.stackid}")

# Prints out a stack trace.
def print_stack(stack_id):
    print(f"t,{stack_id},", end="")
    if (stack_id < 0) and (stack_id != -errno.EFAULT):
        print("[Stack Trace Not Obtained]")
        return
    stack = list(b.get_table("stack_traces").walk(stack_id))
    for i, addr in enumerate(stack):
        print(f"{b.sym(addr, -1, show_module=False, show_offset=True).decode('ascii')}", end="")
        if i < len(stack) - 1:
            print(",", end="")
        else:
            print("")

# This function is called whenever a lock is acquired by a thread, but no more than once per lock+thread per period.
def print_event(cpu, data, size):
    event = b[lock['name']].event(data)
    comm = event.comm.decode("ascii")
    if args.no_filter_monitors or (comm != "collect" and comm != "collectl" and comm != "tcplife-bpfcc"):
        sample = Sample(event.pid_tgid, event.lock_address, event.last_start_time, event.last_diff_sum, event.last_lock_count, event.comm, event.type, event.stack_id)
        if event.stack_id not in used_stack_ids:
            print_stack(event.stack_id)
            used_stack_ids.add(event.stack_id)
        sample.print()

# Argument processing
parser = argparse.ArgumentParser(description='Monitor kernel locking activity in millisecond intervals')
parser.add_argument("--time", help="Amount of seconds to spend collecting samples. Default value: 10", type=int, default=10)
parser.add_argument("--period", help="Period in milliseconds for reporting aggregate data. Default value: 50", type=int, default=50)
parser.add_argument("--no-filter-monitors", help="Disable the automatic filtering of collect, collectl, and tcplife-bpfcc.", action="store_true")
args = parser.parse_args()

# Generating the BPF program
current_pid = os.getpid()
prog = prog_header
for lock in locks:
    prog += lock_func.replace("_ID_", str(lock['id'])).replace("_NAME_", lock['name'])
prog = prog.replace("CUR_PID", str(current_pid))
prog = prog.replace("_PERIOD_", str(args.period))

# Compiling the program and attaching probes to the lock functions
b = BPF(text=prog)
for lock in locks:
    b.attach_kprobe(event=lock['lock_func'], fn_name="lock_%s" % lock['name'])
    b.attach_kretprobe(event=lock['lock_func'], fn_name="release_%s" % lock['name'])

used_stack_ids = set()
sys.stderr.write("Tracing locks for %d seconds\n" % args.time)
sys.stderr.flush()

# Start polling and printing received samples
for lock in locks:
    b[lock['name']].open_perf_buffer(print_event, page_cnt=4096)
start_time = time.time_ns()
end_time = start_time + args.time * 1000 * 1000 * 1000
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
    if end_time < time.time_ns():
        break