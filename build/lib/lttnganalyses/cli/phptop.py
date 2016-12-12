# The MIT License (MIT)
#
# Copyright (C) 2015 - Julien Desfossez <jdesfossez@efficios.com>
#               2015 - Antoine Busque <abusque@efficios.com>
#               2015 - Philippe Proulx <pproulx@efficios.com>
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

import errno
import operator
import statistics
import os
from . import mi
from ..core import phptop
from .command import Command
from . import termgraph
from ..common import format_utils

class LAMPAnalysis(Command):
    _DESC = """The phptop command."""
    _ANALYSIS_CLASS = phptop.PHPAnalysis
    _MI_TITLE = 'Php requests statistics'
    _MI_DESCRIPTION = 'PHP requests statistics'
    _MI_TAGS = [mi.Tags.PHP, mi.Tags.MYSQL]
    _MI_TABLE_CLASS_PER_TID_STATS = 'per tid'
    _MI_TABLE_CLASS_TOTAL = 'total'
    _MI_TABLE_CLASS_TOTAL_APACHE = 'total apache'
    _MI_TABLE_CLASS_TOTAL_LOG = 'log apache'
    _MI_TABLE_CLASS_PER_QUERY_STATS = 'per-query'
    _MI_TABLE_CLASS_FUNCTION_LOG = 'per function log'
    _MI_TABLE_CLASSES = [
        (
            _MI_TABLE_CLASS_PER_TID_STATS,
            'Mysql Query statistics', [
                ('function', 'PhpFunction', mi.String),
                ('filename', 'Filename', mi.String),
                ('lineno', 'Line No', mi.Number),
                ('count', 'Call count', mi.Number, 'calls'),
                ('min_duration', 'Minimum call duration', mi.Duration),
                ('avg_duration', 'Average call duration', mi.Duration),
                ('max_duration', 'Maximum call duration', mi.Duration),
                ('stdev_duration', 'Call duration standard deviation', mi.Duration),
                ('avg_duration_long', 'Duration long', mi.Number),

            ]
        ),
        (
            _MI_TABLE_CLASS_TOTAL,
            'PHP requests statistics', [
                ('tid', 'Request ID', mi.Number),
                ('duration', 'Duration', mi.Duration, 'usec'),
                ('sqlduration', 'DB Execution Duration', mi.Duration, 'usec'),
                ('sqlthreadid', 'DB Connection IDs', mi.Number),
                ('sqlquerycount', 'DB Query Count', mi.Number),
                ('uri', 'Uri', mi.String),
                ('path', 'File Path', mi.String),
                ('method', 'Method', mi.String),
                ('durationlong', 'Duration long', mi.Number),
                ('begin_ts', 'Starting timestamp', mi.Number),
                ('end_ts', 'Ending timestamp', mi.Number),
            ]
        ),
        (
            _MI_TABLE_CLASS_TOTAL_APACHE,
            'Apache requests statistics', [
                ('tid', 'Request ID', mi.Number),
                ('duration', 'Duration', mi.Duration, 'usec'),
                ('phpduration', 'PHP Execution Duration', mi.Duration, 'usec'),
                ('sqlduration', 'DB Execution Duration', mi.Duration, 'usec'),
                ('sqlthreadid', 'DB Connection IDs', mi.Number),
                ('sqlquerycount', 'DB Query Count', mi.Number),
                ('uri', 'Uri', mi.String),
                ('path', 'File Path', mi.String),
                ('method', 'Method', mi.String),
                ('durationlong', 'Duration long', mi.Number),
                ('begin_ts', 'Starting timestamp', mi.Number),
                ('end_ts', 'Ending timestamp', mi.Number),
            ]
        ),
        (
            _MI_TABLE_CLASS_TOTAL_LOG,
            'I/O operations log', [
                ('begin_ts', 'Starting timestamp', mi.Number),
                ('end_ts', 'Ending timestamp', mi.Number),
                ('method', 'System call', mi.Syscall),
                ('uri', 'Uri', mi.String),
                ('path', 'File Path', mi.String),
                ('duration', 'Call duration', mi.Duration),
                ('phpduration', 'PHP Execution Duration', mi.Duration, 'usec'),
                ('sqlduration', 'DB Execution Duration', mi.Duration, 'usec'),
            ]
        ),
        (
            _MI_TABLE_CLASS_PER_QUERY_STATS,
            'Mysql Query statistics', [
                ('query', 'Query', mi.String),
                ('duration', 'Duration', mi.Duration, 'usec'),
                ('tid', 'Connection ID', mi.Number),
                ('db', 'Database', mi.String),
                ('table', 'Table', mi.String),
                ('user', 'User', mi.String),
                ('ret', 'return value', mi.String),
                ('durationlong', 'duration long', mi.Number),
                ('begin_ts', 'starting timestamp', mi.Number)
            ]
        ),
        (
            _MI_TABLE_CLASS_FUNCTION_LOG,
            'PHP function log', [
                ('function', 'Function Name', mi.String),
                ('filename', 'Filename', mi.String),
                ('classname', 'Classname', mi.String),
                ('lineno', 'Lineno', mi.Number),
                ('duration', 'Function duration', mi.Duration),
                ('begin_ts', 'Starting timestamp', mi.Number),
                ('end_ts', 'Ending timestamp', mi.Number),
                ('id', 'Thread ID', mi.Number),
                ('indent', 'Indent', mi.Number),
                ('begin_tslong', 'begin_ts long', mi.Number),
            ]
        ),
    ]

    def _analysis_tick(self, period_data, end_ns):

        if period_data is None:
            return
        begin_ns = period_data.period.begin_evt.timestamp

        php_top_requests__table = self._get_top_php_requessts(period_data, begin_ns, end_ns)
        php_all_requests__table = self._get_all_php_requessts(period_data, begin_ns, end_ns)
        php_per_tid_functions_tables = self._get_functioncalls_per_request(period_data, begin_ns, end_ns)
        #total_requests_table, per_tid_functions_tables = self. _get_functioncalls_per_tid_tables(period_data, begin_ns, end_ns)


        if self._mi_mode:
            self._mi_append_result_table(php_top_requests__table)
            self._mi_append_result_table(php_all_requests__table)

            #self._mi_append_result_table(total_requests_table)
            self._mi_append_result_tables(php_per_tid_functions_tables)
        else:
            self._print_date(begin_ns, end_ns)
            self._print_php_top(php_top_requests__table)
            self._print_php_log(php_all_requests__table)
            self._print_phpfunctions_log(php_all_requests__table, php_per_tid_functions_tables)
            # self._print_phpfunctions_top(total_requests_table, per_tid_functions_tables)

            #self._print_phprequests_summary(php_total_requests__table)

    def _post_analysis(self):
        if not self._mi_mode:
            return

        #if len(self._mi_get_querytypes_per_tid_tables(self._MI_TABLE_CLASS_TOTAL)) > 1:
        #    self._create_summary_result_table()

        self._mi_print()

    def _get_top_php_requessts(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        requestsarray = []
        for tidrequests in period_data.requests.values():
        #for tidrequests in sorted(period_data.requests.values(),
        #                         key=operator.attrgetter('begin_ts'),
        #                         reverse=False):

            if tidrequests.total_requests == 0:
                continue


            for req in tidrequests.requests:
                requestsarray.append(req)

        count = 0

        #for tidrequests in period_data.requests.values():
        for req in sorted(requestsarray,
                          key=operator.attrgetter('duration'),
                          reverse=True):
            #if (req.mysql_threadid is None) or len(req.mysql_threadid <= 0):
            mysql_threadid = 'N/A'
            if req.mysql_threadid is not None:
                mysql_threadid = ",".join(map(str, req.mysql_threadid))

            total_table.append_row(
                tid=mi.Number(req.id),
                duration=mi.Duration(req.duration),
                sqlduration=mi.Duration(req.mysql_duration),
                sqlthreadid=mi.String(mysql_threadid),
                sqlquerycount=mi.String(req.mysql_query_count),
                uri=mi.String(req.uri),
                path=mi.String(req.path),
                method=mi.String(req.method),
                durationlong=mi.Number(req.duration),
                begin_ts=mi.Number(req.begin_ts),
                end_ts = mi.Number(req.end_ts)
            )
            count += 1
            if self._args.limit > 0 and count >= self._args.limit:
                break

        return total_table

    def _get_all_php_requessts(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        requestsarray = []
        for tidrequests in period_data.requests.values():
        #for tidrequests in sorted(period_data.requests.values(),
        #                        key=operator.attrgetter('begin_ts'),
        #                         reverse=False):

            if tidrequests.total_requests == 0:
                continue


            for req in tidrequests.requests:
                requestsarray.append(req)

        count = 0
        for req in sorted(requestsarray,
                          key=operator.attrgetter('begin_ts'),
                          reverse=False):
            #if (req.mysql_threadid is None) or len(req.mysql_threadid <= 0):
            mysql_threadid = 'N/A'
            if req.mysql_threadid is not None:
                mysql_threadid = ",".join(map(str, req.mysql_threadid))

            total_table.append_row(
                tid=mi.Number(req.id),
                duration=mi.Duration(req.duration),
                sqlduration=mi.Duration(req.mysql_duration),
                sqlthreadid=mi.String(mysql_threadid),
                sqlquerycount=mi.String(req.mysql_query_count),
                uri=mi.String(req.uri),
                path=mi.String(req.path),
                method=mi.String(req.method),
                durationlong=mi.Number(req.duration),
                begin_ts=mi.Number(req.begin_ts),
                end_ts = mi.Number(req.end_ts)
            )
            count += 1
            #if self._args.limit > 0 and count >= self._args.limit:
            #    break

        return total_table

    def _get_functioncalls_per_tid_tables(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        # for proc_stats in sorted(self._analysis.phpfunctions.values(),
        #                         key=operator.attrgetter('begin_ts'),
        #                         reverse=False):
        for proc_stats in period_data.phpfunctions.values():
            if proc_stats.total_functions == 0:
                continue
            if proc_stats.tid not in period_data.requests:
                continue

            tidrequests = period_data.requests[proc_stats.tid]
            if tidrequests is None or tidrequests.total_requests == 0:
                continue

            subtitle = '%d' % (proc_stats.tid)
            result_table = \
                self._mi_create_result_table(
                    self._MI_TABLE_CLASS_FUNCTION_LOG, begin_ns, end_ns,
                    subtitle)

            # for singlefunction in sorted(proc_stats.functions.values(),
            #                             key=operator.attrgetter('count'),
            #                             reverse=True):
            for singlefunction in proc_stats.functions.values():
                durations = []
                return_count = {}

                # for function in sorted(singlefunction.call_list,
                #                       key=operator.attrgetter('begin_ts'),
                #                       reverse=True):
                for function in singlefunction.call_list:
                    result_table.append_row(
                        ##FIXME: change this part and add only the required fields like id, class name, begin_ts,
                        #function=mi.PhpFunction(function.name),
                        function=mi.String(function.name),
                        filename=mi.String(function.filename),
                        classname=mi.String(function.classname),
                        lineno=mi.Number(function.lineno),
                        duration=mi.Duration(function.duration),
                        begin_ts=mi.Duration(function.begin_ts),
                        end_ts=mi.Duration(function.end_ts),
                        id=mi.Number(function.id),
                        indent=mi.Number(function.indent),
                        begin_tslong=mi.Number(function.begin_ts)
                    )

            per_tid_tables.append(result_table)

            if tidrequests.total_requests > 1:  # when there is more than one request in tid
                for req in tidrequests.requests:
                    if req.begin_ts.value >= begin_ns and req.end_ts.value <= end_ns:
                        request = req  # fixme
                        break

            else:
                request = tidrequests.requests[0]

            if request is None:
                continue
            # request = tidrequests.requests[0]
            mysql_threadid = 'N/A'
            if request.mysql_threadid is not None:
                mysql_threadid = ",".join(map(str, request.mysql_threadid))

            total_table.append_row(
                tid=mi.Number(request.id),
                duration=mi.Duration(request.duration),
                sqlduration=mi.Duration(request.mysql_duration),
                sqlthreadid=mi.String(mysql_threadid),
                sqlquerycount=mi.String(request.mysql_query_count),
                uri=mi.String(request.uri),
                path=mi.String(request.path),
                method=mi.String(request.method),
                durationlong=mi.Number(request.duration),
                begin_ts=mi.Number(request.begin_ts),
                end_ts=mi.Number(request.end_ts)
            )

        return total_table, per_tid_tables

    def _get_functioncalls_per_tid_tables_orig(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        #for proc_stats in sorted(self._analysis.phpfunctions.values(),
        #                         key=operator.attrgetter('begin_ts'),
        #                         reverse=False):
        for proc_stats in period_data.phpfunctions.values():
            if proc_stats.total_functions == 0:
                continue
            if proc_stats.tid not in period_data.requests:
                continue

            tidrequests = period_data.requests[proc_stats.tid]
            if tidrequests is None or tidrequests.total_requests == 0:
                continue


            subtitle = '%d' % (proc_stats.tid)
            result_table = \
                self._mi_create_result_table(
                    self._MI_TABLE_CLASS_FUNCTION_LOG, begin_ns, end_ns,
                    subtitle)

            #for singlefunction in sorted(proc_stats.functions.values(),
            #                             key=operator.attrgetter('count'),
            #                             reverse=True):
            for singlefunction in proc_stats.functions.values():
                durations = []
                return_count = {}

                #for function in sorted(singlefunction.call_list,
                #                       key=operator.attrgetter('begin_ts'),
                #                       reverse=True):
                for function in singlefunction.call_list:
                     result_table.append_row(
                         ##FIXME: change this part and add only the required fields like id, class name, begin_ts,
                        function=mi.PhpFunction(function.name),
                        filename=mi.String(function.filename),
                        classname=mi.String(function.classname),
                        lineno=mi.Number(function.lineno),
                        duration=mi.Duration(function.duration),
                        begin_ts = mi.Duration(function.begin_ts),
                        end_ts=mi.Duration(function.end_ts),
                        id = mi.Number(function.id),
                        indent=mi.Number(function.indent),
                        begin_tslong = mi.Number(function.begin_ts)
                    )

            per_tid_tables.append(result_table)

            if tidrequests.total_requests > 1:  #when there is more than one request in tid
                for req in tidrequests.requests:
                    if req.begin_ts.value >= begin_ns and req.end_ts.value <= end_ns:
                        request = req   #fixme
                        break

            else:
                request = tidrequests.requests[0]

            if request is None:
                continue
            #request = tidrequests.requests[0]
            mysql_threadid = 'N/A'
            if request.mysql_threadid is not None:
                mysql_threadid = ",".join(map(str, request.mysql_threadid))

            total_table.append_row(
                tid=mi.Number(request.id),
                duration=mi.Duration(request.duration),
                sqlduration=mi.Duration(request.mysql_duration),
                sqlthreadid=mi.String(mysql_threadid),
                sqlquerycount=mi.String(request.mysql_query_count),
                uri=mi.String(request.uri),
                path=mi.String(request.path),
                method=mi.String(request.method),
                durationlong=mi.Number(request.duration),
                begin_ts=mi.Number(request.begin_ts),
                end_ts=mi.Number(request.end_ts)
            )

        return total_table, per_tid_tables

    def _get_functioncalls_per_request(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        for proc_stats in period_data.phpfunctions.values():
            if proc_stats.total_functions == 0:
                continue
            if proc_stats.tid not in period_data.requests:
                continue

            tidrequests = period_data.requests[proc_stats.tid]
            if tidrequests is None or tidrequests.total_requests == 0:
                continue

            subtitle = '%d' % (proc_stats.tid)
            result_table = \
                self._mi_create_result_table(
                    self._MI_TABLE_CLASS_FUNCTION_LOG, begin_ns, end_ns,
                    subtitle)

            for singlefunction in proc_stats.functions.values():
                for function in singlefunction.call_list:
                     result_table.append_row(
                         ##FIXME: change this part and add only the required fields like id, class name, begin_ts,
                        #function=mi.PhpFunction(function.name),
                        function=mi.String(function.name),
                        filename=mi.String(function.filename),
                        classname=mi.String(function.classname),
                        lineno=mi.Number(function.lineno),
                        duration=mi.Duration(function.duration),
                        begin_ts = mi.Duration(function.begin_ts),
                        end_ts=mi.Duration(function.end_ts),
                        id = mi.Number(function.id),
                        indent=mi.Number(function.indent),
                        begin_tslong = mi.Number(function.begin_ts)
                    )

            per_tid_tables.append(result_table)

        return per_tid_tables

    def _get_querytypes_per_tid_tables(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        for proc_stats in sorted(period_data.phpfunctions.values(),
                                 key=operator.attrgetter('begin_ts'),
                                 reverse=False):
            if proc_stats.total_functions == 0:
                continue
            if proc_stats.tid not in period_data.requests:
                continue

            tidrequests = period_data.requests[proc_stats.tid]
            if tidrequests is None or tidrequests.total_requests == 0:
                continue

            subtitle = '%d' % (proc_stats.tid)
            result_table = \
                self._mi_create_result_table(
                    self._MI_TABLE_CLASS_PER_TID_STATS, begin_ns, end_ns,
                    subtitle)

            for function in sorted(proc_stats.functions.values(),
                                   key=operator.attrgetter('count'),
                                   reverse=True):
                durations = []
                return_count = {}

                result_table.append_row(
                    #function=mi.PhpFunction(function.method),
                    function=mi.String(function.method),
                    filename=mi.String(function.filename),
                    lineno=mi.Number(function.lineno),
                    count=mi.Number(function.count),
                    min_duration=mi.Duration(function.min_duration),
                    avg_duration=mi.Duration(function.total_duration /
                                             function.count),
                    max_duration=mi.Duration(function.max_duration),
                    # stdev_duration=stdev,
                    stdev_duration = 0,  # FIXME
                    avg_duration_long = mi.Number(function.total_duration /
                                      function.count)
                )

            per_tid_tables.append(result_table)

            if tidrequests.total_requests > 1:  # when there is more than one request in tid
                for req in tidrequests.requests:
                    if req.begin_ts >= begin_ns and req.end_ts <= end_ns:
                        request = req  # fixme
                        break

            else:
                request = tidrequests.requests[0]

            if request is None:
                continue
            # request = tidrequests.requests[0]
            mysql_threadid = 'N/A'
            if request.mysql_threadid is not None:
                mysql_threadid = ",".join(map(str, request.mysql_threadid))

            total_table.append_row(
                tid=mi.Number(request.id),
                duration=mi.Duration(request.duration),
                sqlduration=mi.Duration(request.mysql_duration),
                sqlthreadid=mi.String(mysql_threadid),
                sqlquerycount=mi.String(request.mysql_query_count),
                uri=mi.String(request.uri),
                path=mi.String(request.path),
                method=mi.String(request.method),
                durationlong=mi.Number(request.duration),
                begin_ts=mi.Number(request.begin_ts),
                end_ts=mi.Number(request.end_ts)
            )
            # total_table.append_row(
            #    phpfunctions=mi.Phpfunctions(name = proc_stats.funcname, tid = proc_stats.tid, file = proc_stats.file),
            #    count=mi.Number(proc_stats.total_functions),
            # )

        return total_table, per_tid_tables

    def _print_phprequests_summary(self, total_table):
        line_format = '{:<10} {:<10} {}'

        print('PHP requests logs:')
        total_requests = 0

        for row in sorted(total_table.rows,
                          key=operator.attrgetter('begin_ts'),
                          reverse=False):
            tid = row.tid.value
            duration = row.duration.to_us()
            sqlduration = row.duration.to_us()
            method = row.method.value
            uri = row.uri.value
            path = row.path.value
            mysql_threadid = row.sqlthreadid.value

            row_format = ' {:<25} {:<6} {:<6} {:<25}  {:<45} {:<10} {:<6} {:<40}'
            # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
            label_header = row_format.format('(% Spent in mysql)', 'TID', 'Method', 'URI', 'PATH', 'SQL TID(s)','Query Count', 'Time Range')

            def format_label(row):
                return row_format.format(
                    # row.duration.to_us(),
                    # row.user.value,
                    # '%.4f (%.2f %)'% (str(row.sqlduration.to_us()) + '('+ str((row.sqlduration.to_us()*100)/row.duration.to_us()) + '%)',

                    '(mysql: %0.02f %%)' % ((row.sqlduration.to_us() * 100) / row.duration.to_us()),
                    # row.sqlduration.to_us(),
                    row.tid.value,
                    row.method.value,
                    row.uri.value,
                    row.path.value,
                    row.sqlthreadid.value,
                    row.sqlquerycount.value,
                    format_utils.format_time_range(
                        row.begin_ts,
                        row.end_ts
                    )
                )

            total_requests += 1

        if total_requests <= 0:
            print('No PHP request!')
            print('-' * 113)
            return

        graph = termgraph.BarGraph(
            title='Duration (us)',
            get_value=lambda row: row.duration.to_us(),
            get_label=format_label,
            label_header=label_header,
            data=sorted(total_table.rows,
                        key=operator.attrgetter('begin_ts'),
                        reverse=False)
        )
        graph.print_graph()

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

    def _print_phpfunctions_top_orig(self, total_table, php_functions_table):
        line_format = '{:<10} {:<10} {}'
        print('Php-Mysql Top:')
        limit = self._args.limit

        total_requests = 0

        row_format = '{:<8} {:<45} {:<15} {:<20} {:<8} {:<15} {:<10} {} '

        # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
        label_header = row_format.format('Method', 'URI', 'Response Time (us)', '(% Spent in mysql)', 'TID', 'SQL TID(s)','Query Count', 'Time Range')
        print(label_header)

        # for row in total_table.rows:
        for row in sorted(total_table.rows,
                          key=operator.attrgetter('durationlong'),
                          reverse=True):
            uri = 'N/A'
            if row.path is None or row.path == '(null)':
                uri = row.uri.value
            else:
                uri = '%s?%s'%(row.uri.value, row.path.value)

            print(row_format.format(
                row.method.value,
                '%s' % (uri),
                #row.path.value,
                '%0.03f' % (row.duration.to_us()),
                '(mysql: %0.03f %%)' % ((row.sqlduration.to_us() * 100) / row.duration.to_us()),
                row.tid.value,
                row.sqlthreadid.value,
                row.sqlquerycount.value,
                format_utils.format_time_range(
                    row.begin_ts,
                    row.end_ts
                )
            ))

            function_format = '{:<7} {:<38} {:>14} {:<14} {:<14} {:<14} {:<12} {:<44}'

            total_queries = 0
            for table in php_functions_table:
                if not table.subtitle == str(row.tid.value):
                    continue

                for subrow in sorted(table.rows,
                                     key=operator.attrgetter('avg_duration_long'),
                                     reverse=True):
                    if subrow is None:
                        continue
                    #if subrow.tid.value not in row.tid.value:
                    #    continue
                    if total_queries == 0: #first row? so print an empty line
                        print(function_format.format('',
                                                  '      ', '', '', '', '', '', ''))
                        print(function_format.format('     ',
                                                 'Function', 'Called', 'Min Duration', 'Average Duration', 'Max Duration',
                                                 'Stdev', 'Location (file:lineno)'))

                    print(function_format.format(
                        '',  # indent!
                        subrow.function.name,
                        subrow.count.value,
                        round(subrow.min_duration.to_us(), 3),
                        round(subrow.avg_duration.to_us(), 3),
                        round(subrow.max_duration.to_us(), 3),
                        subrow.stdev_duration,
                        '%s:%d'%(subrow.filename.value, subrow.lineno.value),
                    ))


                    total_queries += 1
                    if limit is not None and total_queries >= limit:
                        break

            if total_queries > 0:
                print(function_format.format('',
                                      '      ', '', '', '', '', '', ''))
            total_requests += 1
            if limit is not None and total_requests >= limit:
                break

        if total_requests <= 0:
            print('No PHP request!')
            print('-' * 113)
            return

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

    def _print_phpfunctions_top(self, total_table, php_functions_table):
        line_format = '{:<10} {:<10} {}'
        print('Php-Mysql Top:')
        limit = self._args.limit

        total_requests = 0

        row_format = '{:<8} {:<45} {:<15} {:<20} {:<8} {:<15} {:<10} {} '

        # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
        label_header = row_format.format('Method', 'URI', 'Response Time (us)', '(% Spent in mysql)', 'TID',
                                         'SQL TID(s)', 'Query Count', 'Time Range')
        print(label_header)

        for row in total_table.rows:
        #for row in sorted(total_table.rows,
        #                  key=operator.attrgetter('durationlong'),
        #                  reverse=True):
            uri = 'N/A'
            if row.path is None or row.path == '(null)':
                uri = row.uri.value
            else:
                uri = '%s?%s' % (row.uri.value, row.path.value)

            print(row_format.format(
                row.method.value,
                '%s' % (uri),
                # row.path.value,
                '%0.03f' % (row.duration.to_us()),
                '(mysql: %0.03f %%)' % ((row.sqlduration.to_us() * 100) / row.duration.to_us()),
                row.tid.value,
                row.sqlthreadid.value,
                row.sqlquerycount.value,
                format_utils.format_time_range(
                    row.begin_ts.value,
                    row.end_ts.value
                )
            ))

            function_format = '{:<7} {:<38} {:>14} {:<14} {:<14} {:<14} {:<12} {:<44}'

            total_queries = 0
            for table in php_functions_table:
                if not table.subtitle == str(row.tid.value):
                    continue

                for subrow in sorted(table.rows,
                                     key=operator.attrgetter('avg_duration_long'),
                                     reverse=True):
                    if subrow is None:
                        continue
                    # if subrow.tid.value not in row.tid.value:
                    #    continue
                    if total_queries == 0:  # first row? so print an empty line
                        print(function_format.format('',
                                                     '      ', '', '', '', '', '', ''))
                        print(function_format.format('     ',
                                                     'Function', 'Called', 'Min Duration', 'Average Duration',
                                                     'Max Duration',
                                                     'Stdev', 'Location (file:lineno)'))

                    print(function_format.format(
                        '',  # indent!
                        subrow.function.name,
                        subrow.count.value,
                        round(subrow.min_duration.to_us(), 3),
                        round(subrow.avg_duration.to_us(), 3),
                        round(subrow.max_duration.to_us(), 3),
                        subrow.stdev_duration,
                        '%s:%d' % (subrow.filename.value, subrow.lineno.value),
                    ))

                    total_queries += 1
                    if limit is not None and total_queries >= limit:
                        break

            if total_queries > 0:
                print(function_format.format('',
                                             '      ', '', '', '', '', '', ''))
            total_requests += 1
            if limit is not None and total_requests >= limit:
                break

        if total_requests <= 0:
            print('No PHP request!')
            print('-' * 113)
            return

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

    def _print_phpfunctions_log_orig(self, total_table, php_functions_table):
        line_format = '{:<10} {:<10} {}'
        print('Php function logs:')
        limit = self._args.limit

        total_requests = 0

        row_format = '{:<8} {:<45} {:<15} {:<20} {:<8} {:<15} {:<10} {} '

        # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
        label_header = row_format.format('Method', 'URI', 'Response Time (us)', '(% Spent in mysql)', 'TID',
                                         'SQL TID(s)', 'Query Count', 'Time Range')
        print(label_header)

        for row in total_table.rows:
        #for row in sorted(total_table.rows,
        #                  key=operator.attrgetter('durationlong'),
        #                  reverse=True):
            uri = 'N/A'
            if row.path is None or row.path == '(null)':
                uri = row.uri.value
            else:
                uri = '%s?%s' % (row.uri.value, row.path.value)

            print(row_format.format(
                row.method.value,
                '%s' % (uri),
                # row.path.value,
                '%0.03f' % (row.duration.to_us()),
                '(mysql: %0.03f %%)' % ((row.sqlduration.to_us() * 100) / row.duration.to_us()),
                row.tid.value,
                row.sqlthreadid.value,
                row.sqlquerycount.value,
                format_utils.format_time_range(
                    row.begin_ts,
                    row.end_ts
                )
            ))

            #function_format = '{:>10} {:<38} {:<20} {:<14} {:<14} {:<65} {:<35}'
            function_format = '{:>2} {:<30} {:<20} {:<14} {:<8} {:<65} {:<35}'

            total_queries = 0
            for table in php_functions_table:
                if not table.subtitle == str(row.tid.value):
                    continue

                for subrow in sorted(table.rows,
                                     key=operator.attrgetter('begin_tslong'),
                                     reverse=False):
                    if subrow is None:
                        continue

                    #to show only long fuctions!
                    if subrow.duration.to_us() <= 1000:
                        continue;
                    # if subrow.tid.value not in row.tid.value:
                    #    continue
                    indent = ' '
                    for i in range(0, subrow.indent.value):
                        indent += ' '

                    if total_queries == 0:  # first row? so print an empty line
                        print(function_format.format(indent,
                                                     '', '', '', '', '', ''))
                        print(function_format.format('     ',
                                                     'Function', 'Classname', 'duration', 'Tid',
                                                     'Location (file:lineno)','Time Range'))


                    print(function_format.format(
                        indent,
                        '%s  %d' %(subrow.function.name, subrow.indent.value),
                        #subrow.function.name,
                        subrow.classname.value,
                        '%0.03f' % (subrow.duration.to_us()),
                        subrow.id.value,
                        '%s:%d' % (subrow.filename.value, subrow.lineno.value),
                        format_utils.format_time_range(
                            subrow.begin_ts.value,
                            subrow.end_ts.value
                        ),
                    ))

                    total_queries += 1
                    #if limit is not None and total_queries >= limit:
                    #    break

            if total_queries > 0:
                print(function_format.format('',
                                          '      ', '', '', '', '', '', ''))
            total_requests += 1
            if limit is not None and total_requests >= limit:
                break

        if total_requests <= 0:
            print('No PHP request!')
            print('-' * 113)
            return

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)
    def _print_phpfunctions_log(self, total_table, php_functions_table):
        line_format = '{:<10} {:<10} {}'
        print('Php function logs:')
        limit = self._args.limit

        total_requests = 0

        row_format = '{:<8} {:<45} {:<15} {:<20} {:<8} {:<15} {:<10} {} '

        # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
        label_header = row_format.format('Method', 'URI', 'Response Time (us)', '(% Spent in mysql)', 'TID',
                                         'SQL TID(s)', 'Query Count', 'Time Range')
        print(label_header)

        for row in total_table.rows:
        #for row in sorted(total_table.rows,
        #                  key=operator.attrgetter('durationlong'),
        #                  reverse=True):
            uri = 'N/A'
            if row.path is None or row.path == '(null)':
                uri = row.uri.value
            else:
                uri = '%s?%s' % (row.uri.value, row.path.value)

            print(row_format.format(
                row.method.value,
                '%s' % (uri),
                # row.path.value,
                '%0.03f' % (row.duration.to_us()),
                '(mysql: %0.03f %%)' % ((row.sqlduration.to_us() * 100) / row.duration.to_us()),
                row.tid.value,
                row.sqlthreadid.value,
                row.sqlquerycount.value,
                format_utils.format_time_range(
                    row.begin_ts.value,
                    row.end_ts.value
                )
            ))

            #function_format = '{:>10} {:<38} {:<20} {:<14} {:<14} {:<65} {:<35}'
            function_format = '{:>2} {:<30} {:<20} {:<14} {:<8} {:<65} {:<35}'

            total_queries = 0
            for table in php_functions_table:
                if not table.subtitle == str(row.tid.value):
                    continue

                for subrow in table.rows:
                #for subrow in sorted(table.rows,
                #                     key=operator.attrgetter('begin_tslong'),
                #                     reverse=False):
                    if subrow is None:
                        continue

                    #to show only long fuctions!
                    #if subrow.duration.to_us() <= 1000:
                    #    continue;
                    # if subrow.tid.value not in row.tid.value:
                    #    continue
                    indent = ' '
                    for i in range(0, subrow.indent.value):
                        indent += ' '

                    if total_queries == 0:  # first row? so print an empty line
                        print(function_format.format(indent,
                                                     '', '', '', '', '', ''))
                        print(function_format.format('     ',
                                                     'Function', 'Classname', 'duration', 'Tid',
                                                     'Location (file:lineno)','Time Range'))


                    print(function_format.format(
                        indent,
                        '%s  %d' %(subrow.function.name, subrow.indent.value),
                        #subrow.function.name,
                        subrow.classname.value,
                        '%0.03f' % (subrow.duration.to_us()),
                        subrow.id.value,
                        '%s:%d' % (subrow.filename.value, subrow.lineno.value),
                        format_utils.format_time_range(
                            subrow.begin_ts.value,
                            subrow.end_ts.value
                        ),
                    ))

                    total_queries += 1
                    #if limit is not None and total_queries >= limit:
                    #    break

            if total_queries > 0:
                #print(function_format.format('',
                #                          '      ', '', '', '', '', '', ''))
                print(function_format.format('Total Function Calls for This Request:',
                                     '      ', total_queries, '', '', '', '', ''))
            total_requests += 1
            if limit is not None and total_requests >= limit:
                break

        if total_requests <= 0:
            print('No PHP request!')
            print('-' * 113)
            return

        print(line_format.format('Total PHP Requests:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

    def _print_phpmysql_top_old(self, total_table, mysql_query_table):
        line_format = '{:<10} {:<10} {}'
        print('Php-Mysql Top:')
        limit = self._args.limit

        total_requests = 0

        row_format = '{:<8} {:<45} {:<15} {:<20} {:<8} {:<15} {:<10} {} '

        # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
        label_header = row_format.format('Method', 'URI', 'Response Time', '(% Spent in mysql)', 'TID', 'SQL TID(s)',
                                         'Query Count', 'Time Range')
        print(label_header)

        # for row in total_table.rows:
        for row, table in zip(sorted(total_table.rows,
                                     key=operator.attrgetter('durationlong'),
                                     reverse=True),
                              mysql_query_table):
            uri = 'N/A'
            if row.path is None or row.path == '(null)':
                uri = row.uri.value
            else:
                uri = '%s?%s' % (row.uri.value, row.path.value)

            print(row_format.format(
                row.method.value,
                '%s' % (uri),
                # row.path.value,
                '%0.03f' % (row.duration.to_us()),
                '(mysql: %0.03f %%)' % ((row.sqlduration.to_us() * 100) / row.duration.to_us()),
                row.tid.value,
                row.sqlthreadid.value,
                row.sqlquerycount.value,
                format_utils.format_time_range(
                    row.begin_ts,
                    row.end_ts
                )
            ))
            query_format = '{:<7} {:<42} {:<15} {:<25} {:<10} {:<10} {:<35}'
            total_queries = 0
            for subrow in sorted(table.rows,
                                 key=operator.attrgetter('durationlong'),
                                 reverse=True):
                if subrow is None:
                    continue
                # if subrow.tid.value not in row.tid.value:
                #    continue
                # if total_queries == 0: #first row? so print an empty line
                #    print(query_format.format(table.subtitle,
                #                              '      ','', '', '', '','', ''))
                print(query_format.format(
                    '      ',
                    format_utils.format_time_range(
                        subrow.begin_ts,
                        subrow.begin_ts
                    ),
                    '%0.03f' % (subrow.duration.to_us()),
                    subrow.tid.value,
                    '%s@%s' % (subrow.user.value, subrow.db.value),
                    subrow.query.value.replace(os.linesep, ' '),
                    subrow.ret.value
                ))
                total_queries += 1
                if limit is not None and total_queries >= limit:
                    break

            print(query_format.format(table.subtitle,
                                      '      ', '', '', '', '', '', ''))
            total_requests += 1
            if limit is not None and total_requests >= limit:
                break

        if total_requests <= 0:
            print('No PHP request!')
            print('-' * 113)
            return

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

    def _print_php_top(self, total_table):
        line_format = '{:<10} {:<10} {}'
        print('Php Top Requests:')
        #limit = self._args.limit

        total_requests = 0

        row_format = '{:<42} {:<15} {:<25} {:<10} {:<10} {:<50} {:<12} {:<10}'
        # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
        label_header = row_format.format('Time Range', 'Response Time', '(% Spent in mysql)', 'TID', 'Method', 'URI',
                                         'SQL TID(s)', 'No of SQL Query')
        print(label_header)

        for row in total_table.rows:
        #for row in sorted(total_table.rows,
        #                  key=operator.attrgetter('durationlong'),
        #                  reverse=True):
            tid = row.tid.value
            duration = row.duration.to_us()
            sqlduration = row.duration.to_us()
            method = row.method.value
            uri = row.uri.value
            path = row.path.value
            mysql_threadid = row.sqlthreadid.value
            time_range_str = format_utils.format_time_range(
                row.begin_ts.value,
                row.end_ts.value
            )
            uri = 'N/A'
            if row.path.value is None:
                uri = row.uri.value
            else:
                uri = '%s?%s' % (row.uri.value, row.path.value)

            print(row_format.format(
                time_range_str,
                '%0.03f' % (row.duration.to_us()),
                '(mysql: %0.03f %%)' % ((row.sqlduration.to_us() * 100) / row.duration.to_us()),
                row.tid.value,
                row.method.value,
                '%s' % (uri),
                row.sqlthreadid.value,
                row.sqlquerycount.value
            ))

            total_requests += 1

            #if limit is not None and total_requests >= limit:
            #    break

        if total_requests <= 0:
            print('No PHP request!')
            print('-' * 113)
            return

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

    def _print_php_log(self, total_table):
        line_format = '{:<10} {:<10} {}'
        print('Php All Requests:')
        # limit = self._args.limit

        total_requests = 0

        row_format = '{:<42} {:<15} {:<25} {:<10} {:<10} {:<50} {:<12} {:<10}'
        # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
        label_header = row_format.format('Time Range', 'Response Time', '(% Spent in mysql)', 'TID', 'Method', 'URI',
                                         'SQL TID(s)', 'No of SQL Query')
        print(label_header)

        for row in total_table.rows:
            # for row in sorted(total_table.rows,
            #                  key=operator.attrgetter('durationlong'),
            #                  reverse=True):
            tid = row.tid.value
            duration = row.duration.to_us()
            sqlduration = row.duration.to_us()
            method = row.method.value
            uri = row.uri.value
            path = row.path.value
            mysql_threadid = row.sqlthreadid.value
            time_range_str = format_utils.format_time_range(
                row.begin_ts.value,
                row.end_ts.value
            )
            uri = 'N/A'
            if row.path.value is None:
                uri = row.uri.value
            else:
                uri = '%s?%s' % (row.uri.value, row.path.value)

            print(row_format.format(
                time_range_str,
                '%0.03f' % (row.duration.to_us()),
                '(mysql: %0.03f %%)' % ((row.sqlduration.to_us() * 100) / row.duration.to_us()),
                row.tid.value,
                row.method.value,
                '%s' % (uri),
                row.sqlthreadid.value,
                row.sqlquerycount.value
            ))

            total_requests += 1

            # if limit is not None and total_requests >= limit:
            #    break

        if total_requests <= 0:
            print('No PHP request!')
            print('-' * 113)
            return

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

    def _print_php_top_orig(self, total_table):
        line_format = '{:<10} {:<10} {}'
        print('Php Top:')
        #limit = self._args.limit

        total_requests = 0

        row_format ='{:<42} {:<15} {:<25} {:<10} {:<10} {:<50} {:<12} {:<10}'
        # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
        label_header = row_format.format('Time Range', 'Response Time', '(% Spent in mysql)', 'TID', 'Method', 'URI', 'SQL TID(s)','No of SQL Query')
        print(label_header)

        for row in total_table.rows:
        #for row in sorted(total_table.rows,
        #                  key=operator.attrgetter('durationlong'),
        #                  reverse=True):
            tid = row.tid.value
            duration = row.duration.to_us()
            sqlduration = row.duration.to_us()
            method = row.method.value
            uri = row.uri.value
            path = row.path.value
            mysql_threadid = row.sqlthreadid.value
            time_range_str = format_utils.format_time_range(
                row.begin_ts.value,
                row.end_ts.value
            )
            uri = 'N/A'
            if row.path.value is None:
                uri = row.uri.value
            else:
                uri = '%s?%s'%(row.uri.value, row.path.value)

            print(row_format.format(
                time_range_str,
                '%0.03f' % (row.duration.to_us()),
                '(mysql: %0.03f %%)' % ((row.sqlduration.to_us() * 100) / row.duration.to_us()),
                row.tid.value,
                row.method.value,
                '%s' % (uri),
                row.sqlthreadid.value,
                row.sqlquerycount.value
            ))

            total_requests += 1

            #if limit is not None and total_requests >= limit:
            #    break

        if total_requests <= 0:
            print('No PHP request!')
            print('-' * 113)
            return

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

    def _print_mysql_top(self, result_table):
        line_format = '{:<5} {:<10} {:<10} {:<10} {} {:>14}'

        print('Mysql Top:')
        total_queries = 0
        limit = self._args.limit


        print(line_format.format('TID', 'Duration', 'User', 'Database', 'Return', 'Query'))

        for row in sorted(result_table.rows,
                          key=operator.attrgetter('durationlong'),
                          reverse=True):
            # for row in result_table.rows:
            tid = row.tid.value
            query_duration = row.duration.to_us()
            query_name = row.query.value
            ret = row.ret.value
            db = row.db.value
            user = row.user.value

            total_queries += 1
            print(line_format.format(tid, query_duration, user, db, ret, query_name.replace(os.linesep, ' ')))

            if limit is not None and total_queries >= limit:
                break

        print('-' * 113)
        print('\nTotal queries: %d' % (total_queries))

        ''' #showing by bargraph
        row_format = '  {:<30} {:>14} {:>14} {:>14}'
        label_header = row_format.format('Query', 'Duration', 'Connection ID', 'Return')

        def format_label(row):
            return row_format.format(
                '%s' % (row.query), row.duration.to_us(),
                row.tid.value,
                row.ret.value
            )

        graph = termgraph.BarGraph(
            title='Per-Query Mysql Statistics',
            get_value=lambda row: row.duration.to_us(),
            get_label=format_label,
            label_header=label_header,
            data=result_table.rows
        )
        graph.print_graph()'''

    def _add_arguments(self, ap):
        Command._add_proc_filter_args(ap)
        Command._add_min_max_args(ap)
        Command._add_log_args(
            ap, help='Output the Lamp requests in chronological order')
        Command._add_top_args(
            ap, help='Output the top Lamp latencies by category')
        Command._add_stats_args(ap, help='Output the Lamp latency statistics')
        Command._add_freq_args(
            ap, help='Output the Lamp latency frequency distribution')
        ap.add_argument('--usage', action='store_true',
                        help='Output the Lamp usage')
        ap.add_argument('--minsize', type=float,
                        help='Filter out, Lamp operations working with '
                             'less that minsize bytes')
        ap.add_argument('--maxsize', type=float,
                        help='Filter out, Lamp operations working with '
                             'more that maxsize bytes')



def _run(mi_mode):
    syscallscmd = LAMPAnalysis(mi_mode=mi_mode)
    syscallscmd.run()


# entry point (human)
def run():
    _run(mi_mode=False)
    #_run(mi_mode=True)



# entry point (MI)
def run_mi():
    _run(mi_mode=True)
