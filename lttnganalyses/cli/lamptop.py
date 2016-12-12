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
from ..common import format_utils
from ..core import lamptop
from .command import Command
from . import termgraph
from . import mi

class LAMPAnalysis(Command):
    _DESC = """The lamptop command."""
    _ANALYSIS_CLASS = lamptop.LAMPAnalysis
    _MI_TITLE = 'LAMP top requests'
    _MI_DESCRIPTION = 'LAMP top requests'
    _MI_TAGS = [mi.Tags.PHP, mi.Tags.APACHE, mi.Tags.MYSQL, mi.Tags.TOP]
    _MI_TABLE_CLASS_TOTAL_APACHE = 'apache'
    _MI_TABLE_CLASS_TOTAL_PHP = 'php'
    _MI_TABLE_CLASS_TOTAL_MYSQL = 'mysql'
    _MI_TABLE_CLASS_TOTAL_LOG = 'log apache'
    _MI_TABLE_CLASS_PER_QUERY_STATS = 'per-query'
    _MI_TABLE_CLASS_TOTAL = 'per-request'

    _MI_TABLE_CLASSES = [
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
            'Apache top requests', [
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
                # ('count', 'Call count', mi.Number, 'calls'),
            ]
        ),
        (
            _MI_TABLE_CLASS_TOTAL_PHP,
            'Php top requests', [
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
                # ('count', 'Call count', mi.Number, 'calls'),
            ]
        ),
        (
            _MI_TABLE_CLASS_TOTAL_MYSQL,
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
    ]

    #def _analysis_tick(self, begin_ns, end_ns):
    def _analysis_tick(self, period_data, end_ns):

        if period_data is None:
            return
        begin_ns = period_data.period.begin_evt.timestamp

        apache_top_requests__table = self._get_apache_top_requests(period_data, begin_ns, end_ns)
        php_top_requests__table1 = self._get_php_top_requests(period_data, begin_ns, end_ns)
        mysql_top_queries__table = self._get_top_queries_tables(period_data,begin_ns, end_ns)

        #apache_all_requests__table = self._get_apache_all_requests(period_data, begin_ns, end_ns)
        #php_all_requests__table1 = self._get_php_all_requests(period_data, begin_ns, end_ns)
        #mysql_all_queries__table = self._get_all_queries_tables(period_data, begin_ns, end_ns)

        #php_total_requests__table, php_mysql_quries = self._get_phpmysql_per_tid_phpreqests_tables(period_data, begin_ns, end_ns)

        # self._get_querytypes_per_dbtable_tables(begin_ns, end_ns)

        if self._mi_mode:
            self._mi_append_result_table(apache_top_requests__table)
            self._mi_append_result_table(php_top_requests__table1)
            self._mi_append_result_table(mysql_top_queries__table)



            #self._mi_append_result_table(apache_all_requests__table)
            #self._mi_append_result_table(php_all_requests__table1)
            #self._mi_append_result_table(mysql_all_queries__table)
            #self._mi_append_result_table(php_total_requests__table1)

        else:
            self._print_date(begin_ns, end_ns)

            self._print_apache_top(apache_top_requests__table)
            self._print_php_top(php_top_requests__table1)
            self._print_mysql_top(mysql_top_queries__table)

            #self._print_apache_log(apache_all_requests__table)
            #self._print_php_log(php_all_requests__table1)
            #self._print_mysql_log(mysql_all_queries__table)
            #self._print_phpmysql_top(php_total_requests__table1, php_mysql_quries)

            # self._print_apacherequests_summary(apache_total_requests__table)
            # self._print_phprequests_summary(php_total_requests__table1)

    def _post_analysis(self):
        if not self._mi_mode:
            return

        # if len(self._mi_get_querytypes_per_tid_tables(self._MI_TABLE_CLASS_TOTAL)) > 1:
        #    self._create_summary_result_table()

        self._mi_print()

    def _create_summary_result_tables(self):
        total_tables = self._mi_get_result_tables(self._MI_TABLE_CLASS_TOTAL)
        begin = total_tables[0].timerange.begin.value
        end = total_tables[-1].timerange.end.value
        summary_table = \
            self._mi_create_result_table(self._MI_TABLE_CLASS_SUMMARY,
                                         begin, end)

        for total_table in total_tables:
            usage = total_table.rows[0].usage
            summary_table.append_row(
                time_range=total_table.timerange,
                usage=usage,
            )

        self._mi_clear_result_tables()
        self._mi_append_result_table(summary_table)

    def _get_phpmysql_per_tid_phpreqests_tables(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        for requests in sorted(period_data.requests.values(),
                               key=operator.attrgetter('count'),
                               reverse=False):
            if requests.total_requests == 0:
                continue

            # subtitle = 'top queries for request: '

            count = 0
            for req in requests.request_list:
                subtitle = str(req.id)
                result_table = \
                    self._mi_create_result_table(
                        self._MI_TABLE_CLASS_PER_QUERY_STATS, begin_ns, end_ns,
                        subtitle)
                # if (req.mysql_threadid is None) or len(req.mysql_threadid <= 0):
                mysql_threadid = 'N/A'
                if req.mysql_threadid is not None:
                    mysql_threadid = ",".join(map(str, req.mysql_threadid))

                    for mysql_tid in req.mysql_threadid:
                        for query in period_data.mysqlqueries[mysql_tid].query_list:
                            if query.ret == 0:
                                return_key = 'success'
                            else:
                                try:
                                    return_key = errno.errorcode[-query.ret]
                                except KeyError:
                                    return_key = str(query.ret)
                            result_table.append_row(
                                query=mi.String(query.query),
                                duration=mi.Duration(query.duration),
                                tid=mi.Number(query.id),
                                db=mi.String(query.db),
                                table=mi.String(query.table),
                                user=mi.String(query.user),
                                ret=mi.String(return_key),
                                durationlong=query.duration,
                                begin_ts=query.begin_ts
                            )
                            count += 1
                per_tid_tables.append(result_table)

                total_table.append_row(
                    tid=mi.Number(req.id),
                    duration=mi.Duration(req.duration),
                    sqlduration=mi.Duration(req.mysql_duration),
                    sqlthreadid=mi.String(mysql_threadid),
                    sqlquerycount=mi.String(req.mysql_query_count),
                    uri=mi.String(req.uri),
                    path=mi.String(req.query_string),
                    method=mi.String(req.method),
                    durationlong=req.duration,
                    begin_ts=req.begin_ts,
                    end_ts=req.end_ts
                )
                count += 1
                # per_tid_tables.append(result_table)

        return total_table, per_tid_tables

    def _get_apache_top_requests_orig(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL_APACHE,
                                                   begin_ns, end_ns)

        for requests in sorted(period_data.apacherequests.values(),
                               #key=operator.attrgetter('count'),total_duration
                               key=operator.attrgetter('total_duration'),
                               reverse=True):
            if requests.total_requests == 0:
                continue
            count = 0

            for req in requests.request_list:
            #for req in requests.request_list:
                # if (req.mysql_threadid is None) or len(req.mysql_threadid <= 0):
                mysql_threadid = ''
                if not req.mysql_threadid:
                    mysql_threadid = ",".join(map(str, req.mysql_threadid))

                total_table.append_row(
                    tid=mi.Number(req.id),
                    duration=mi.Duration(req.duration),
                    phpduration=mi.Duration(req.php_duration),
                    sqlduration=mi.Duration(req.mysql_duration),
                    sqlthreadid=mi.String(mysql_threadid),
                    sqlquerycount=mi.String(req.mysql_query_count),
                    uri=mi.String(req.uri),
                    path=mi.String(req.path),
                    method=mi.String(req.method),
                    durationlong=mi.Number(req.duration),
                    begin_ts=mi.Number(req.begin_ts),
                    end_ts=mi.Number(req.end_ts),
                    # count=mi.Number(count),
                )
                count += 1
        # per_tid_tables.append(total_table)
        return total_table
        # return per_tid_tables

    def _get_apache_top_requests(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL_APACHE,
                                                   begin_ns, end_ns)
        requestsarray = []
        for requests in period_data.apacherequests.values():
        #for requests in sorted(period_data.apacherequests.values(),
        #                       # key=operator.attrgetter('count'),total_duration
        #                       key=operator.attrgetter('total_duration'),
        #                       reverse=True):
            if requests.total_requests == 0:
                continue

            for req in requests.request_list:
                requestsarray.append(req)

        count = 0
        for req in sorted(requestsarray,
                          key=operator.attrgetter('duration'),
                          reverse=True):
            # for req in requests.request_list:
            # if (req.mysql_threadid is None) or len(req.mysql_threadid <= 0):
            mysql_threadid = ''
            if not req.mysql_threadid:
                mysql_threadid = ",".join(map(str, req.mysql_threadid))

            total_table.append_row(
                tid=mi.Number(req.id),
                duration=mi.Duration(req.duration),
                phpduration=mi.Duration(req.php_duration),
                sqlduration=mi.Duration(req.mysql_duration),
                sqlthreadid=mi.String(mysql_threadid),
                sqlquerycount=mi.String(req.mysql_query_count),
                uri=mi.String(req.uri),
                path=mi.String(req.path),
                method=mi.String(req.method),
                durationlong=mi.Number(req.duration),
                begin_ts=mi.Number(req.begin_ts),
                end_ts=mi.Number(req.end_ts),
                # count=mi.Number(count),
            )
            count += 1
            if self._args.limit > 0 and count >= self._args.limit:
                break
        # per_tid_tables.append(total_table)
        return total_table
        # return per_tid_tables

    def _get_apache_all_requests(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL_APACHE,
                                                   begin_ns, end_ns)
        requestsarray = []
        for requests in period_data.apacherequests.values():
        #for requests in sorted(period_data.apacherequests.values(),
                               # key=operator.attrgetter('count'),total_duration
        #                       key=operator.attrgetter('total_duration'),
        #                       reverse=True):
            if requests.total_requests == 0:
                continue

            for req in requests.request_list:
                requestsarray.append(req)

        count = 0
        for req in sorted(requestsarray,
                          key=operator.attrgetter('begin_ts'),
                          reverse=False):
            # for req in requests.request_list:
            # if (req.mysql_threadid is None) or len(req.mysql_threadid <= 0):
            mysql_threadid = ''
            if not req.mysql_threadid:
                mysql_threadid = ",".join(map(str, req.mysql_threadid))

            total_table.append_row(
                tid=mi.Number(req.id),
                duration=mi.Duration(req.duration),
                phpduration=mi.Duration(req.php_duration),
                sqlduration=mi.Duration(req.mysql_duration),
                sqlthreadid=mi.String(mysql_threadid),
                sqlquerycount=mi.String(req.mysql_query_count),
                uri=mi.String(req.uri),
                path=mi.String(req.path),
                method=mi.String(req.method),
                durationlong=mi.Number(req.duration),
                begin_ts=mi.Number(req.begin_ts),
                end_ts=mi.Number(req.end_ts),
                # count=mi.Number(count),
            )
            count += 1

        # per_tid_tables.append(total_table)
        return total_table
        # return per_tid_tables

    def _get_php_top_requests(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL_PHP,
                                                   begin_ns, end_ns)
        requestsarray = []
        for requests in period_data.requests.values():
        #for requests in sorted(period_data.requests.values(),
        #                       key=operator.attrgetter('count'),
        #                       reverse=False):

            if requests.total_requests == 0:
                continue

            for req in requests.request_list:
                requestsarray.append(req)

        count = 0
        for req in sorted(requestsarray,
                                  key=operator.attrgetter('duration'),
                                  reverse=True):
            mysql_threadid = 'N/A'
            # if req.mysql_threadid is not None:
            if req.mysql_threadid is not None and len(req.mysql_threadid) > 0:
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
                durationlong=mi.Duration(req.duration),
                begin_ts=mi.Number(req.begin_ts),
                end_ts=mi.Number(req.end_ts)
            )

            count += 1
            if self._args.limit > 0 and count >= self._args.limit:
                break

        return total_table

    def _get_php_all_requests(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL_PHP,
                                                   begin_ns, end_ns)
        requestsarray = []
        for requests in period_data.requests.values():

            if requests.total_requests == 0:
                continue


            for req in requests.request_list:
                requestsarray.append(req)

        count = 0
        for req in sorted(requestsarray,
                                  key=operator.attrgetter('begin_ts'),
                                  reverse=False):
            mysql_threadid = 'N/A'
            # if req.mysql_threadid is not None:
            if req.mysql_threadid is not None and len(req.mysql_threadid) > 0:
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
                durationlong=mi.Duration(req.duration),
                begin_ts=mi.Number(req.begin_ts),
                end_ts=mi.Number(req.end_ts)
            )

            count += 1


        return total_table

    def _get_top_queries_tables(self, period_data, begin_ns, end_ns):
        subtitle = ''
        result_table = \
            self._mi_create_result_table(
                self._MI_TABLE_CLASS_TOTAL_MYSQL, begin_ns, end_ns, subtitle)

        requestsarray = []
        for proc_stats in period_data.mysqlqueries.values():
            if proc_stats.total_queries == 0:
                continue

            for query in proc_stats.query_list:
                requestsarray.append(query)

        count = 0
        for query in sorted(requestsarray,
                                  key=operator.attrgetter('duration'),
                                  reverse=True):
                if query.ret == 0:
                    return_key = 'success'
                else:
                    try:
                        return_key = errno.errorcode[-query.ret]
                    except KeyError:
                        return_key = str(query.ret)
                result_table.append_row(
                    query=mi.String(query.query),
                    duration=mi.Duration(query.duration),
                    tid=mi.Number(query.id),
                    db=mi.String(query.db),
                    table=mi.String(query.table),
                    user=mi.String(query.user),
                    ret=mi.String(return_key),
                    durationlong=mi.Number(query.duration),
                    begin_ts=mi.Number(query.begin_ts),

                )
                count += 1
                if self._args.limit > 0 and count >= self._args.limit:
                    break

        return result_table

    def _get_all_queries_tables(self, period_data, begin_ns, end_ns):
        subtitle = ''
        result_table = \
            self._mi_create_result_table(
                self._MI_TABLE_CLASS_TOTAL_MYSQL, begin_ns, end_ns, subtitle)

        requestsarray = []
        for proc_stats in period_data.mysqlqueries.values():
            if proc_stats.total_queries == 0:
                continue

            for query in proc_stats.query_list:
                requestsarray.append(query)

        count = 0
        for query in sorted(requestsarray,
                          key=operator.attrgetter('begin_ts'),
                          reverse=False):
            if query.ret == 0:
                return_key = 'success'
            else:
                try:
                    return_key = errno.errorcode[-query.ret]
                except KeyError:
                    return_key = str(query.ret)
            result_table.append_row(
                query=mi.String(query.query),
                duration=mi.Duration(query.duration),
                tid=mi.Number(query.id),
                db=mi.String(query.db),
                table=mi.String(query.table),
                user=mi.String(query.user),
                ret=mi.String(return_key),
                durationlong=mi.Number(query.duration),
                begin_ts=mi.Number(query.begin_ts),

            )
            count += 1
            #if self._args.limit > 0 and count >= self._args.limit:
            #    break

        return result_table

    def _print_apacherequests_summary(self, total_table):
        line_format = '{:<10} {:<10} {}'

        #print('Apache requests logs:')
        total_requests = 0
        # for row in total_table.rows:
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
            time_range_str = format_utils.format_time_range(
                row.begin_ts.value,
                row.end_ts.value
            )

            row_format = ' {:<50} {:<10} {:<10} {:<60} {:<40}'
            # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
            label_header = row_format.format('% Spent in php and mysql', 'TID', 'Method', 'URI', 'Time Range')

            def format_label(row):
                return row_format.format(
                    # row.duration.to_us(),
                    # row.user.value,
                    # '%.4f (%.2f %)'% (str(row.sqlduration.to_us()) + '('+ str((row.sqlduration.to_us()*100)/row.duration.to_us()) + '%)',
                    # '%0.02f (%0.02f %%)' % (
                    # row.sqlduration.to_us(), (row.sqlduration.to_us() * 100) / row.duration.to_us()),
                    # row.sqlduration.to_us(),

                    '(apache: %0.03f %%, php: %0.03f %%, mysql: %0.03f %%)' % (
                        ((row.duration.to_us() - row.phpduration.to_us()) * 100) / row.duration.to_us(),
                        ((row.phpduration.to_us() - row.sqlduration.to_us()) * 100) / row.duration.to_us(),
                        (row.sqlduration.to_us() * 100) / row.duration.to_us()),

                    row.tid.value,
                    row.method.value,

                    '%s%s' % (row.path.value, row.uri.value),
                    format_utils.format_time_range(
                        row.begin_ts,
                        row.end_ts
                    )

                    # row.sqlthreadid.value
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

    def _print_apache_top(self, total_table):
        line_format = '{:<10} {:<10} {}'

        print('Apache Top Requests:')

        #limit = self._args.limit

        total_requests = 0

        row_format = '{:<42} {:<15} {:<55} {:<10}{:<10} {}'
        label_header = row_format.format('Time Range', 'Response Time', '(% Spent in php and mysql)', 'TID', 'Method',
                                         'URI')
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

            print(row_format.format(
                time_range_str,
                '% 0.03f' % (row.duration.to_us()),
                ' (apache: %0.03f %%, php: %0.03f %%, mysql: %0.03f %%)' % (
                    ((row.duration.to_us() - row.phpduration.to_us()) * 100) / row.duration.to_us(),
                    ((row.phpduration.to_us() - row.sqlduration.to_us()) * 100) / row.duration.to_us(),
                    (row.sqlduration.to_us() * 100) / row.duration.to_us()
                ),
                row.tid.value,
                row.method.value,
                '%s%s' % (row.path.value, row.uri.value)
            ))

            total_requests += 1
            #if limit is not None and total_requests >= limit:
            #    break

        if total_requests <= 0:
            print('No Apache Request!')
            print('-' * 113)
            return

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

    def _print_apache_log(self, total_table):
        line_format = '{:<10} {:<10} {}'

        print('All Apache Requests:')

        #limit = self._args.limit

        total_requests = 0

        row_format = '{:<42} {:<15} {:<55} {:<10}{:<10} {}'
        label_header = row_format.format('Time Range', 'Response Time', '(% Spent in php and mysql)', 'TID', 'Method',
                                         'URI')
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

            print(row_format.format(
                time_range_str,
                '% 0.03f' % (row.duration.to_us()),
                ' (apache: %0.03f %%, php: %0.03f %%, mysql: %0.03f %%)' % (
                    ((row.duration.to_us() - row.phpduration.to_us()) * 100) / row.duration.to_us(),
                    ((row.phpduration.to_us() - row.sqlduration.to_us()) * 100) / row.duration.to_us(),
                    (row.sqlduration.to_us() * 100) / row.duration.to_us()
                ),
                row.tid.value,
                row.method.value,
                '%s%s' % (row.path.value, row.uri.value)
            ))

            total_requests += 1
            #if limit is not None and total_requests >= limit:
            #    break

        if total_requests <= 0:
            print('No Apache Request!')
            print('-' * 113)
            return

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

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
            label_header = row_format.format('(% Spent in mysql)', 'TID', 'Method', 'URI', 'PATH', 'SQL TID(s)',
                                             'Query Count', 'Time Range')

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

    def _print_phpmysql_top(self, total_table, mysql_query_table):
        line_format = '{:<10} {:<10} {}'
        print('Php-Mysql Top:')
        #limit = self._args.limit

        total_requests = 0

        row_format = '{:<8} {:<45} {:<15} {:<20} {:<8} {:<15} {:<10} {} '

        # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
        label_header = row_format.format('Method', 'URI', 'Response Time (us)', '(% Spent in mysql)', 'TID',
                                         'SQL TID(s)', 'Query Count', 'Time Range')
        print(label_header)

        # for row in total_table.rows:
        for row in sorted(total_table.rows,
                          key=operator.attrgetter('durationlong'),
                          reverse=True):
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
            query_format = '{:<7} {:<42} {:<15} {:<10} {:<10} {:<10} {:<35}'
            total_queries = 0
            for table in mysql_query_table:
                if not table.subtitle == str(row.tid.value):
                    continue

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
                        '      ',  # indent!
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
                    #if limit is not None and total_queries >= limit:
                    #    break

            if total_queries > 0:
                print(query_format.format('',
                                          '      ', '', '', '', '', '', ''))
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
        print('All Php Requests:')
        #limit = self._args.limit

        total_requests = 0

        row_format = '{:<42} {:<15} {:<25} {:<10} {:<10} {:<50} {:<12} {:<10}'
        # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
        label_header = row_format.format('Time Range', 'Response Time', '(% Spent in mysql)', 'TID', 'Method', 'URI',
                                         'SQL TID(s)', 'No of SQL Query')
        print(label_header)

        for row in total_table.rows:
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

        if total_requests <= 0:
            print('No PHP request!')
            print('-' * 113)
            return

        print(line_format.format('Total:', total_requests,
                                 '', '', '', '', ''))
        print('-' * 113)

    def _print_mysql_top(self, result_table):
        line_format = '{:<5} {:<10} {:<10} {:<10} {} {:>14}'

        print('Mysql Top Queries:')
        total_queries = 0
        #limit = self._args.limit

        print(line_format.format('TID', 'Duration', 'User', 'Database', 'Return', 'Query'))

        for row in result_table.rows:
        #for row in sorted(result_table.rows,
        #                  key=operator.attrgetter('durationlong'),
        #                  reverse=True):
            # for row in result_table.rows:
            tid = row.tid.value
            query_duration = row.duration.to_us()
            query_name = row.query.value
            ret = row.ret.value
            db = row.db.value
            user = row.user.value

            total_queries += 1
            print(line_format.format(tid, query_duration, user, db, ret, query_name.replace(os.linesep, ' ')))

            #if limit is not None and total_queries >= limit:
            #    break

        print('-' * 113)
        print('\nTotal queries: %d' % (total_queries))

    def _print_mysql_log(self, result_table):
        line_format = '{:<5} {:<10} {:<10} {:<10} {} {:>14}'

        print('All Mysql Queries:')
        total_queries = 0
        #limit = self._args.limit

        print(line_format.format('TID', 'Duration', 'User', 'Database', 'Return', 'Query'))

        for row in result_table.rows:
            # for row in sorted(result_table.rows,
            #                  key=operator.attrgetter('durationlong'),
            #                  reverse=True):
            # for row in result_table.rows:
            tid = row.tid.value
            query_duration = row.duration.to_us()
            query_name = row.query.value
            ret = row.ret.value
            db = row.db.value
            user = row.user.value

            total_queries += 1
            print(line_format.format(tid, query_duration, user, db, ret, query_name.replace(os.linesep, ' ')))

            #if limit is not None and total_queries >= limit:
            #    break

        print('-' * 113)
        print('\nTotal queries: %d' % (total_queries))


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
    lamtopcmd = LAMPAnalysis(mi_mode=mi_mode)
    lamtopcmd.run()


# entry point (human)
def run():
    _run(mi_mode=False)
    #_run(mi_mode=True)


# entry point (MI)
def run_mi():
    _run(mi_mode=True)
