# The MIT License (MIT)
#
# Copyright (C) 2015 - Antoine Busque <abusque@efficios.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from collections import namedtuple


PrioEvent = namedtuple('PrioEvent', ['timestamp', 'prio'])


class Stats():
    def reset(self):
        raise NotImplementedError()


class Process(Stats):
    def __init__(self, pid, tid, comm):
        self.pid = pid
        self.tid = tid
        self.comm = comm
        self.prio_list = []

    @classmethod
    def new_from_process(cls, proc):
        return cls(proc.pid, proc.tid, proc.comm)

    def update_prio(self, timestamp, prio):
        self.prio_list.append(PrioEvent(timestamp, prio))

    def reset(self):
        if self.prio_list:
            # Keep the last prio as the first for the next period
            self.prio_list = self.prio_list[-1:]


class IO(Stats):
    def __init__(self):
        # Number of bytes read or written
        self.read = 0
        self.write = 0

    def reset(self):
        self.read = 0
        self.write = 0

    def __iadd__(self, other):
        self.read += other.read
        self.write += other.write
        return self

class MySqlThreads(Stats):
    def __init__(self, tid, name, ts):
        self.tid = tid
        self.name = name
        self.begin_ts = ts
        self.query_list = []

    @classmethod
    def new_from_thread(cls, connection):
        return cls(connection.id, connection.name, connection.begin_ts)

    def query_add(self, query):
        self.query_list.append(query)

    def update_prio(self, connection):
        self.query_list.append(connection)

    def reset(self):
        if self.query_list:
            # Keep the last prio as the first for the next period
            self.query_list = self.query_list[-1:]

class MySqlTables(Stats):
    def __init__(self, table, name, ts, duration):
        if table is None:
            table = 'unknown'
        self.table = table

        if name is None:
            name = 'unknown'
        self.name = name + '.' + table

        self.begin_ts = ts
        self.query_list = []
        self.duration = duration
        #self.count += 1

    @classmethod
    def new_from_table(cls, query):
        return cls(query.table, query.db, query.begin_ts, query.duration)



    def update_prio(self, connection):
        self.query_list.append(connection)

    def reset(self):
        if self.query_list:
            # Keep the last prio as the first for the next period
            self.query_list = self.query_list[-1:]

class PhpRequests(Stats):
    def __init__(self, tid, method, uri, ts, duration):
        self.tid = tid
        self.uri = uri
        self.method = method
        self.begin_ts = ts
        self.duration = duration
        self.requests_list = []

    @classmethod
    def new_from_request(cls, request):
        return cls(request.id, request.method, request.uri, request.begin_ts, request.duration)

class PhpFunctions(Stats):
    def __init__(self, tid, funcname, file, classname, lineno, ts, duration):
        self.tid = tid
        self.funcname = funcname
        self.filename = file
        self.classname = classname
        self.lineno = lineno
        self.begin_ts = ts
        self.duration = duration
        self.functions_list = []

    @classmethod
    def new_from_function(cls, function):
        return cls(function.id, function.name, function.filename, function.classname, function.lineno, function.begin_ts, function.duration)

class ApacheRequests(Stats):
    def __init__(self, tid, method, uri, ts, duration):
        self.tid = tid
        self.uri = uri
        self.method = method
        self.begin_ts = ts
        self.duration = duration
        self.requests_list = []

    @classmethod
    def new_from_request(cls, request):
        return cls(request.id, request.method, request.uri, request.begin_ts, request.duration)
