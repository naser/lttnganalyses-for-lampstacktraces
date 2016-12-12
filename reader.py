#!/usr/bin/python3

import babeltrace.reader
import sys
import time



trace_collection = babeltrace.reader.TraceCollection()

args = sys.argv[1:]
for trace_path in args:
    trace_collection.add_trace(trace_path, 'ctf')


start_time = time.time()

for event in trace_collection.events:
    pass 

elapsed_time = time.time() - start_time

print(elapsed_time)
