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
#from .analysis import Analysis
from .analysis import Analysis, PeriodData


class _PeriodData(PeriodData):
    def __init__(self):
        self.period_begin_ts = None
        self.requests = {}
        self.apacherequests = {}
        self.mysqlqueries = {}
        self.indent = 0
        self.request_id = 0
        self.total_requests = 0

class LAMPAnalysis(Analysis):
    def __init__(self, state, conf):
        notification_cbs = {
            'ust_php:request_exit': self._php_request_exit,
            'ust_apache:request_exit': self._apache_request_exit,
            'ust_mysql:query_done': self._mysql_query_done,

        }
        super().__init__(state, conf, notification_cbs)
        #super().__init__(state, conf)
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

    def _php_request_entry(self, period_data, **kwargs):
        cpu_id = kwargs['cpu_id']
        method = kwargs['method']
        path = kwargs['path']
        uri = kwargs['uri']
        period_data.request_id += 1
        output = '-> %s %s' % (method, uri)
        print(output)
        #print('-> ' + method + " " + uri + " " + timestamp)

    def _php_request_exit(self, period_data, **kwargs):
        cpu_id = kwargs['cpu_id']
        id = kwargs['id']
        method = kwargs['method']
        path = kwargs['path']
        uri = kwargs['uri']
        duration = kwargs['duration']
        request = kwargs['request']

        if uri not in period_data.requests: #FIXME
            period_data.requests[uri] = PhpRequestsStats.new_from_request(request)
            period_data.requests[uri]= PhpStats(uri)

        period_data.requests[uri].update_stats(request)
        period_data.total_requests += 1

        #output = '<- %s %s?%s  (%d ns)' % (method, uri, request.query_string, duration)
        #print (output)

    def _apache_request_exit(self, period_data, **kwargs):
        cpu_id = kwargs['cpu_id']
        id = kwargs['id']
        method = kwargs['method']
        host = kwargs['host']
        uri = kwargs['uri']
        duration = kwargs['duration']
        request = kwargs['request']

        if uri not in period_data.apacherequests:
            period_data.apacherequests[uri] = ApacheRequestsStats.new_from_request(request)
            period_data.apacherequests[uri] = ApacheStats(uri)

        period_data.apacherequests[uri].update_stats(request)
        period_data.total_requests += 1

        # output = '<- %s %s?%s  (%d ns)' % (method, uri, request.query_string, duration)
        # print (output)

    def _mysql_query_done(self, period_data, **kwargs):
        cpu_id = kwargs['cpu_id']
        result = kwargs['result']
        thread_id = kwargs['thread_id']
        duration = kwargs['duration']  # ns
        query = kwargs['query']
        connection = kwargs['connection']
        name = query.type

        #fixme: uncomment this!
        #if not self._filter_mysql(connection, query):
        #    return

        if thread_id not in period_data.mysqlqueries:
            period_data.mysqlqueries[thread_id] = ThreadMysqlStats.new_from_thread(connection)

        proc_stats = period_data.mysqlqueries[thread_id]
        proc_stats.update_stats(query)
        #proc_stats.query_add(query)
        #if thread_id not in proc_stats.queries:
        #    proc_stats.queries[name] = MysqlStats(name)
        #proc_stats.update_stats(query)
        #proc_stats.queries[name].update_stats(query)



class PhpRequestsStats(stats.PhpRequests):
    def __init__(self, tid, method, uri, ts, duration):
        super().__init__(tid, method, uri, ts, duration)

        # indexed by uri
        self.requests = {}
        self.total_requests = 0
        self.total_duration = 0
        self.average_duration = 0

    def reset(self):
        pass

class PhpStats():
    def __init__(self, uri):
        self.uri = uri
        self.min_duration = None
        self.max_duration = None
        self.total_duration = 0
        self.total_requests = 0
        #self.average = 0
        self.request_list = []

    @property
    def count(self):
        return len(self.request_list)

    def update_stats(self, query):
        duration = query.duration
        #print (duration)

        if self.min_duration is None or self.min_duration > duration:
            self.min_duration = duration
        if self.max_duration is None or self.max_duration < duration:
            self.max_duration = duration

        self.total_requests += 1
        self.total_duration += duration
        self.request_list.append(query)

class ApacheRequestsStats(stats.ApacheRequests):
    def __init__(self, tid, method, uri, ts, duration):
        super().__init__(tid, method, uri, ts, duration)

        # indexed by uri
        self.requests = {}
        self.total_requests = 0
        self.total_duration = 0
        self.average_duration = 0

    def reset(self):
        pass

class ApacheStats():
    def __init__(self, uri):
        self.uri = uri
        self.min_duration = None
        self.max_duration = None
        self.total_duration = 0
        self.total_requests = 0
        #self.average = 0
        self.request_list = []

    @property
    def count(self):
        return len(self.request_list)

    def update_stats(self, query):
        duration = query.duration

        if self.min_duration is None or self.min_duration > duration:
            self.min_duration = duration
        if self.max_duration is None or self.max_duration < duration:
            self.max_duration = duration

        self.total_requests += 1
        self.total_duration += duration
        self.request_list.append(query)

class ThreadMysqlStats(stats.MySqlThreads):
    def __init__(self, tid, name, ts):
        super().__init__(tid, name, ts)

        # indexed by query type
        #self.queries = {}

        self.total_queries = 0
        self.total_duration = 0

    def update_stats(self, query):
        self.total_queries += 1
        self.total_duration += query.duration
        self.query_list.append(query)

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
