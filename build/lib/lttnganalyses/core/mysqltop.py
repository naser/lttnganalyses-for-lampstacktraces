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

from . import stats
from .analysis import Analysis, PeriodData
import sys, os


class _PeriodData(PeriodData):
    def __init__(self):
        self.queries = {}
        self.tids = {}
        self.tables = {}
        self.total_queries = 0

class MYSQLAnalysis(Analysis):
    def __init__(self, state, conf):
        notification_cbs = {
            'ust_mysql:query_start': self._mysql_query_start,
            'ust_mysql:query_done': self._mysql_query_done,
        }

        super().__init__(state, conf, notification_cbs)
        #self._state.register_notification_cbs(notification_cbs)

    def _create_period_data(self):
        return _PeriodData()

    def _begin_period_cb(self, period_data):
        period = period_data.period
        period_data.period_begin_ts = period.begin_evt.timestamp

    def _end_period_cb(self, period_data, completed, begin_captures,
                       end_captures):
        self._compute_stats(period_data)

    def reset(self):
        # FIXME why no reset?
        pass

    def _compute_stats(self, period_data):
        """Compute usage stats relative to a certain time range

        For each CPU and process tracked by the analysis, we set its
        usage_percent attribute, which represents the percentage of
        usage time for the given CPU or process relative to the full
        duration of the time range. Do note that we need to know the
        timestamps and not just the duration, because if a CPU or a
        process is currently busy, we use the end timestamp to add
        the partial results of the currently running task to the usage
        stats.
        """
        duration = self.last_event_ts - period_data.period.begin_evt.timestamp


    def _mysql_query_start(self, period_data, **kwargs):
        cpu_id = kwargs['cpu_id']
        query = kwargs['query']
        thread_id = kwargs['thread_id']
        db = kwargs['db']


    def _mysql_query_done(self, period_data, **kwargs):
        cpu_id = kwargs['cpu_id']
        result = kwargs['result']
        thread_id = kwargs['thread_id']
        #duration = kwargs['duration'] / 1000000  #ms
        duration = kwargs['duration']  #ns
        query = kwargs['query']
        connection = kwargs['connection']
        name = query.type

        #if not period_data._filter_mysql(connection, query):
        #    return

        if thread_id not in period_data.tids:
            period_data.tids[thread_id] = ThreadMysqlStats.new_from_thread(connection)

        proc_stats = period_data.tids[thread_id]
        if name not in proc_stats.queries:
            proc_stats.queries[name] = MysqlStats(name)

        proc_stats.queries[name].update_stats(query)
        proc_stats.total_queries += 1

        #'per table stats'
        table = query.table
        if table is None:
            table = 'unknown'
        if table not in period_data.tables:
            period_data.tables[table] = TableMysqlStats.new_from_table(query)
        #print (query.query)
        #if (table == 'role_permission'):
        #    print (table)
        table_stats = period_data.tables[table]
        if name not in table_stats.queries:
            table_stats.queries[name] = MysqlStats(name)

        table_stats.queries[name].update_stats(query)
        table_stats.total_queries += 1
        table_stats.total_duration += query.duration
        table_stats.average_duration =  table_stats.total_duration / table_stats.total_queries

        #self.queries.update_stats(query)
        #if name not in self.queries:
        #    self.queries[name] = MysqlStats(name)
        #self.queries[name].update_stats(query)
        period_data.total_queries += 1

        output = '<- cpu: %d thread_id: %s result: %s duration: %d (ns)' % (cpu_id, thread_id, result, duration)
        #print (output)

class ThreadMysqlStats(stats.MySqlThreads):
    def __init__(self, tid, name, ts):
        super().__init__(tid, name, ts)

        # indexed by query type
        self.queries = {}
        self.total_queries = 0

    def reset(self):
        pass

class TableMysqlStats(stats.MySqlTables):
    def __init__(self, table, name, ts, duration):
        super().__init__(table, name, ts, duration)

        # indexed by query type
        self.queries = {}
        self.total_queries = 0
        self.total_duration = 0
        self.average_duration = 0

    def reset(self):
        pass

class MysqlStats():
    def __init__(self, name):
        self.name = name
        self.min_duration = None
        self.max_duration = None
        self.total_duration = 0
        self.total_queries = 0
        #self.average = 0
        self.query_list = []

    @property
    def count(self):
        return len(self.query_list)

    def update_stats(self, query):
        duration = query.duration

        if self.min_duration is None or self.min_duration > duration:
            self.min_duration = duration
        if self.max_duration is None or self.max_duration < duration:
            self.max_duration = duration

        self.total_queries += 1
        self.total_duration += duration
        self.query_list.append(query)