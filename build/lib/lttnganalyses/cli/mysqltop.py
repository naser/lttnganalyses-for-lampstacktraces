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
from ..core import mysqltop
from .command import Command
from . import termgraph

class MYSQLAnalysis(Command):
    _DESC = """The mysqltop command."""
    _ANALYSIS_CLASS = mysqltop.MYSQLAnalysis
    _MI_TITLE = 'Mysql Query statistics'
    _MI_DESCRIPTION = 'Per-TID and global Myaql query statistics'
    _MI_TAGS = [mi.Tags.MYSQL, mi.Tags.PHP]
    _MI_TABLE_CLASS_PER_TID_STATS = 'per-tid'
    _MI_TABLE_CLASS_PER_QUERY_STATS = 'per-query'
    _MI_TABLE_CLASS_TOTAL = 'total'
    _MI_TABLE_CLASS_SUMMARY = 'summary'
    _MI_TABLE_CLASSES = [
        (
            _MI_TABLE_CLASS_PER_TID_STATS,
            'Mysql Query statistics', [
                ('query', 'Query', mi.String),
                ('count', 'Call count', mi.Number, 'calls'),
                ('min_duration', 'Minimum call duration', mi.Duration),
                ('avg_duration', 'Average call duration', mi.Duration),
                ('max_duration', 'Maximum call duration', mi.Duration),
                ('stdev_duration', 'Call duration standard deviation',
                 mi.Duration),
                ('return_values', 'Return values count', mi.String),
            ]
        ),
        (
            _MI_TABLE_CLASS_TOTAL,
            'Per-TID Mysql Query statistics', [
                ('mysqlthreads', 'Mysqlthreads', mi.Mysqlthreads),
                ('count', 'Total Mysql Query count', mi.Number, 'calls'),
            ]
        ),
        (
            _MI_TABLE_CLASS_SUMMARY,
            'Mysql Query statistics - summary', [
                ('time_range', 'Time range', mi.TimeRange),
                ('mysqlthreads', 'Mysqlthreads', mi.Mysqlthreads),
                ('count', 'Total Mysql Query count', mi.Number, 'calls'),
            ]
        ),
        (
            _MI_TABLE_CLASS_PER_QUERY_STATS,
            'Mysql All Queries', [
                ('query', 'Query', mi.Mysql),
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

    def _analysis_tick(self, period_data, end_ns):
        if period_data is None:
            return
        begin_ns = period_data.period.begin_evt.timestamp
        
        total_table, per_tid_tables = self._get_querytypes_per_tid_tables(period_data, begin_ns, end_ns)
        total_dbtable_table, per_dbtable_tables = self._get_querytypes_per_dbtable_tables(period_data, begin_ns, end_ns)
        total_tid_query_table, query_per_tid_tables = self._get_per_tid_queries_tables(period_data, begin_ns, end_ns)
        total_dbtable_query_table, query_per_dbtable_tables = self._get_per_dbtable_queries_tables(period_data, begin_ns, end_ns)
        per_query_table = self._get_all_queries_tables(period_data, begin_ns, end_ns)



        if self._mi_mode:
            #self._mi_append_result_table(total_table)
            #self._mi_append_result_table(total_dbtable_table)
            #self._mi_append_result_table(total_tid_query_table)
            #self._mi_append_result_table(total_dbtable_query_table)
            #self._mi_append_result_table(per_query_table)

            self._mi_append_result_tables(per_tid_tables)
            self._mi_append_result_tables(per_dbtable_tables)
            self._mi_append_result_tables(query_per_tid_tables)
            self._mi_append_result_tables(query_per_dbtable_tables)

            self._mi_append_result_table(per_query_table)


        else:
            self._print_date(begin_ns, end_ns)
            self._print_per_tid_summary_results(total_table, per_tid_tables)
            self._print_per_dbtable_summary_results(total_dbtable_table, per_dbtable_tables)
            self._print_per_tid_queries_results(total_tid_query_table, query_per_tid_tables)
            self._print_per_table_queries_results(total_dbtable_query_table, query_per_dbtable_tables)
            self._print_all_queries_tables(per_query_table)

    def _post_analysis(self):
        if not self._mi_mode:
            return

        #if len(self._mi_get_querytypes_per_tid_tables(self._MI_TABLE_CLASS_TOTAL)) > 1:
        #self._create_summary_result_table()

        self._mi_print()

    def _create_summary_result_table(self):
        total_tables = self._mi_get_result_tables(self._MI_TABLE_CLASS_TOTAL) #self._mi_get_querytypes_per_tid_tables(self._MI_TABLE_CLASS_TOTAL)
        begin = total_tables[0].timerange.begin.value
        end = total_tables[-1].timerange.end.value
        summary_table = \
            self._mi_create_result_table(self._MI_TABLE_CLASS_SUMMARY,
                                         begin, end)

        for total_table in total_tables:
            for row in total_table.rows:
                process = row.process
                count = row.count
                summary_table.append_row(
                    time_range=total_table.timerange,
                    process=process,
                    count=count,
                )

        self._mi_clear_result_tables()
        self._mi_append_result_table(summary_table)

    def _get_querytypes_per_tid_tables(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        #for proc_stats in period_data.tids.values():
        for proc_stats in sorted(period_data.tids.values(),
                                 key=operator.attrgetter('begin_ts'),
                                 reverse=False):
            if proc_stats.total_queries == 0:
                continue

            subtitle = '%s (ID: %d)' % (proc_stats.name, proc_stats.tid)
            result_table = \
                self._mi_create_result_table(
                    self._MI_TABLE_CLASS_PER_TID_STATS, begin_ns, end_ns,
                    subtitle)

            for queryType in sorted(proc_stats.queries.values(),
                                  key=operator.attrgetter('count'),
                                  reverse=True):
                durations = []
                return_count = {}

                for query in queryType.query_list:
                    durations.append(query.duration)

                    if query.ret == 0:
                        return_key = 'success'
                    else:
                        try:
                            return_key = errno.errorcode[-query.ret]
                        except KeyError:
                            return_key = str(query.ret)

                    if return_key not in return_count:
                        return_count[return_key] = 1
                    else:
                        return_count[return_key] += 1

                if len(durations) > 2:
                    stdev = mi.Duration(statistics.stdev(durations))
                else:
                    stdev = mi.Unknown()

                result_table.append_row(
                    query=mi.Mysql(queryType.name),
                    count=mi.Number(queryType.count),
                    min_duration=mi.Duration(queryType.min_duration),
                    avg_duration=mi.Duration(queryType.total_duration /
                                             queryType.count),
                    max_duration=mi.Duration(queryType.max_duration),
                    stdev_duration=stdev,
                    return_values=mi.String(str(return_count)),
                )

            per_tid_tables.append(result_table)
            total_table.append_row(
                mysqlthreads=mi.Mysqlthreads(proc_stats.name, tid=proc_stats.tid),
                count=mi.Number(proc_stats.total_queries),
            )

        return total_table, per_tid_tables

    def _get_per_dbtable_queries_tables(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        for proc_stats in sorted(period_data.tables.values(),
                                 # key=operator.attrgetter('total_queries'),
                                 key=operator.attrgetter('average_duration'),
                                 reverse=False):
            if proc_stats.total_queries == 0:
                continue

            subtitle = 'db.table: %s ' % (proc_stats.table)
            result_table = \
                self._mi_create_result_table(
                    self._MI_TABLE_CLASS_PER_QUERY_STATS, begin_ns, end_ns,
                    subtitle)
            count = 0

            for queryType in sorted(proc_stats.queries.values(),
                                    key=operator.attrgetter('count'),
                                    reverse=True):
                durations = []
                return_count = {}

                for query in queryType.query_list:

                    if query.ret == 0:
                        return_key = 'success'
                    else:
                        try:
                            return_key = errno.errorcode[-query.ret]
                        except KeyError:
                            return_key = str(query.ret)

                    result_table.append_row(
                        query=mi.String(query.query.replace(os.linesep, ' ')),
                        duration=mi.Duration(query.duration),
                        tid=mi.Number(query.id),
                        db=mi.String(query.db),
                        table=mi.String(query.table),
                        user=mi.String(query.user),
                        ret=mi.String(return_key),
                        durationlong=mi.Duration(query.duration),
                        begin_ts=mi.Number(query.begin_ts)
                    )
                    count += 1

            per_tid_tables.append(result_table)
            total_table.append_row(
                mysqlthreads=mi.Mysqlthreads(proc_stats.name,table = proc_stats.table),
                count=mi.Number(proc_stats.total_queries),
            )

        return total_table, per_tid_tables

    def _get_per_tid_queries_tables(self, period_data, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        for proc_stats in sorted(period_data.tids.values(),
                                 #key=operator.attrgetter('total_queries'),
                                 key=operator.attrgetter('begin_ts'),
                                 reverse=False):
            if proc_stats.total_queries == 0:
                continue

            subtitle = 'TID: %d ' % (proc_stats.tid)
            result_table = \
                self._mi_create_result_table(
                    self._MI_TABLE_CLASS_PER_QUERY_STATS, begin_ns, end_ns,
                    subtitle)
            count = 0

            for queryType in sorted(proc_stats.queries.values(),
                                    key=operator.attrgetter('count'),
                                    reverse=True):
                durations = []
                return_count = {}

                for query in queryType.query_list:

                    if query.ret == 0:
                        return_key = 'success'
                    else:
                        try:
                            return_key = errno.errorcode[-query.ret]
                        except KeyError:
                            return_key = str(query.ret)

                    result_table.append_row(
                        query=mi.String(query.query.replace(os.linesep, ' ')),
                        duration=mi.Duration(query.duration),
                        tid=mi.Number(query.id),
                        db=mi.String(query.db),
                        table=mi.String(query.table),
                        user=mi.String(query.user),
                        ret=mi.String(return_key),
                        durationlong=mi.Duration(query.duration),
                        begin_ts=mi.Number(query.begin_ts)
                    )
                    count += 1

            per_tid_tables.append(result_table)
            total_table.append_row(
                mysqlthreads=mi.Mysqlthreads(proc_stats.name, tid=proc_stats.tid),
                count=mi.Number(proc_stats.total_queries),
            )

        return total_table, per_tid_tables

    def _get_all_queries_tables(self, period_data, begin_ns, end_ns):
        subtitle = ''
        result_table = \
            self._mi_create_result_table(
                self._MI_TABLE_CLASS_PER_QUERY_STATS, begin_ns, end_ns, subtitle)
        count = 0

        requestsarray = []
        for proc_stats in period_data.tids.values():
        #for proc_stats in sorted(period_data.tids.values(),
        #                         key=operator.attrgetter('begin_ts'),
        #                         reverse=False):
            if proc_stats.total_queries == 0:
                continue

            for queryType in proc_stats.queries.values():
            #for queryType in sorted(proc_stats.queries.values(),
            #                        key=operator.attrgetter('count'),
            #                        reverse=True):
                if queryType.count == 0:
                    continue

                for query in queryType.query_list:
                    requestsarray.append(query)

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

                    '''result_table.append_row(
                        query=mi.Mysql(query.query),
                        duration=mi.Duration(query.duration),
                        tid=mi.Number(query.id),
                        ret=mi.String(return_key)
                    )'''
                    result_table.append_row(
                        query=mi.String(query.query),
                        duration=mi.Duration(query.duration),
                        tid=mi.Number(query.id),
                        db=mi.String(query.db),
                        table=mi.String(query.table),
                        user=mi.String(query.user),
                        ret=mi.String(return_key),
                        durationlong = mi.Number(query.duration),
                        begin_ts = mi.Number(query.begin_ts)
                    )
                    count += 1
                    #if self._args.limit > 0 and count >= self._args.limit:
                    #    break

        return result_table

    def _get_querytypes_per_dbtable_tables(self, period_data, begin_ns, end_ns):
        per_dbtable_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        for dbtable_stats in sorted(period_data.tables.values(),
                                 key=operator.attrgetter('average_duration'),
                                 reverse=True):
            if dbtable_stats.total_queries == 0:
                continue

            subtitle = 'Table:%s' % (dbtable_stats.name)
            result_table = \
                self._mi_create_result_table(
                    self._MI_TABLE_CLASS_PER_TID_STATS, begin_ns, end_ns,
                    subtitle)

            for queryType in sorted(dbtable_stats.queries.values(),
                                    key=operator.attrgetter('count'),
                                    reverse=True):
                durations = []
                return_count = {}

                for query in queryType.query_list:
                    durations.append(query.duration)

                    if query.ret == 0:
                        return_key = 'success'
                    else:
                        try:
                            return_key = errno.errorcode[-query.ret]
                        except KeyError:
                            return_key = str(query.ret)

                    if return_key not in return_count:
                        return_count[return_key] = 1
                    else:
                        return_count[return_key] += 1

                if len(durations) > 2:
                    stdev = mi.Duration(statistics.stdev(durations))
                else:
                    stdev = mi.Unknown()

                result_table.append_row(
                    query=mi.Mysql(queryType.name),
                    count=mi.Number(queryType.count),
                    min_duration=mi.Duration(queryType.min_duration),
                    avg_duration=mi.Duration(queryType.total_duration /
                                             queryType.count),
                    max_duration=mi.Duration(queryType.max_duration),
                    stdev_duration=stdev,
                    return_values=mi.String(str(return_count)),
                )

            per_dbtable_tables.append(result_table)
            total_table.append_row(
                mysqlthreads=mi.Mysqlthreads(dbtable_stats.name, tid=dbtable_stats.table),
                count=mi.Number(dbtable_stats.total_queries),
            )

        return total_table, per_dbtable_tables

    def _print_all_queries_tables(self, result_table):
        line_format = '{:<5} {:<10} {:<10} {:<10} {} {:>14}'

        print('Per-Query mysql statistics (usec)')
        total_calls = 0

        print(line_format.format('TID', 'Duration', 'User', 'Database', 'Return', 'Query'))

        for row in result_table.rows:
        #for row in sorted(result_table.rows,
        #       key=operator.attrgetter('durationlong'),
        #       reverse=True):
        #for row in result_table.rows:
            tid = row.tid.value
            query_duration = row.duration.to_us()
            query_name = row.query.value
            ret = row.ret.value
            db = row.db.value
            '''if row.table.value is None:
                db = row.db.value
            else:
                db = row.db.value + '.' + row.table.value'''
            user = row.user.value

            total_calls += 1
            print(line_format.format(tid, query_duration, user, db, ret, query_name.replace(os.linesep, ' ')))

        print('-' * 113)
        print('\nTotal queries: %d' % (total_calls))


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


    def _print_per_table_queries_results(self, total_table, per_tid_tables):
        # line_format = '{:<5} {:<10} {:<10} {:<10} {} {:>14}'
        # line_format = '{:<45} {:<10} {:<10} {:<10} {}'
        line_format = '{:<10} {:<10} {}'

        print('Per-db.table query detailts')
        total_calls = 0

        for total_row, table in zip(total_table.rows, per_tid_tables):
            proc_total_calls = 0
            # print(line_format.format(table.subtitle, 'Duration', 'User', 'Database', 'Return', 'Query'))
            ##for row in sorted(table.rows,
            ##                  key=operator.attrgetter('begin_ts'),
            ##                  reverse=True):
            for row in table.rows:
                tid = row.tid.value
                query_duration = row.duration.to_us()
                query_name = row.query.value
                ret = row.ret.value
                db = row.db.value
                if db is None:
                    db = 'unkown'
                user = row.user.value
                dbtable = row.table.value
                if dbtable is None:
                    dbtable = 'unkown'

                proc_total_calls += 1

                # row_format = line_format
                row_format = '  {:<10} {:>10}  {}'
                label_header = row_format.format('Database', 'Return', 'Query')

                # label_header = line_format.format(table.subtitle, 'Duration(us)', 'User', 'Database', 'Return', 'Query')
                # label_header = line_format.format('Duration(us) ', 'Database', 'Return', 'Query')

                def format_label(row):
                    return row_format.format(
                        # row.duration.to_us(),
                        # row.user.value,
                        row.db.value,
                        row.ret.value,
                        row.query.value
                    )

                graph = termgraph.BarGraph(
                    title='Queries for ' + str(db + '.' + dbtable) + ' , user: ' + user + '       Duration (us)',
                    get_value=lambda row: row.duration.to_us(),
                    get_label=format_label,
                    label_header=label_header,
                    data=table.rows
                    ##data=sorted(table.rows,
                    ##            key=operator.attrgetter('begin_ts'),
                    ##            reverse=False)
                )
                # graph.print_graph()
                ####
                # print(line_format.format(tid, query_duration, user, db, ret, query_name.replace(os.linesep, ' ')))
            # proc_total_calls = total_row.count.value
            graph.print_graph()
            # print('-' * 113)
            # print(line_format.format('Total:', proc_total_calls,
            print(line_format.format('Total:', proc_total_calls,
                                     '', '', '', '', ''))
            print('-' * 113)
            total_calls += proc_total_calls

        print('\nTotal queries: %d' % (total_calls))

    def _print_per_tid_queries_results(self, total_table, per_tid_tables):
        #line_format = '{:<5} {:<10} {:<10} {:<10} {} {:>14}'
        #line_format = '{:<45} {:<10} {:<10} {:<10} {}'
        line_format = '{:<10} {:<10} {}'

        print('Per-TID mysql query detailts')
        total_calls = 0

        for total_row, table in zip(total_table.rows, per_tid_tables):
            proc_total_calls = 0
            #print(line_format.format(table.subtitle, 'Duration', 'User', 'Database', 'Return', 'Query'))
            ##for row in sorted(table.rows,
            ##                  key=operator.attrgetter('begin_ts'),
            ##                  reverse=False):
            for row in table.rows:
                tid = row.tid.value
                query_duration = row.duration.to_us()
                query_name = row.query.value
                ret = row.ret.value
                db = row.db.value
                user = row.user.value

                proc_total_calls += 1

                #row_format = line_format
                row_format = '  {:<10} {:>10}  {}'
                label_header = row_format.format('Database', 'Return', 'Query')
                #label_header = line_format.format(table.subtitle, 'Duration(us)', 'User', 'Database', 'Return', 'Query')
                #label_header = line_format.format('Duration(us) ', 'Database', 'Return', 'Query')

                def format_label(row):
                    return row_format.format(
                        #row.duration.to_us(),
                        #row.user.value,
                        row.db.value,
                        row.ret.value,
                        row.query.value
                    )

                graph = termgraph.BarGraph(
                    title='Queries for TID: '+ str(tid) + ' , user: ' + user + '       Duration (us)',
                    get_value=lambda row: row.duration.to_us(),
                    get_label=format_label,
                    label_header=label_header,
                    data = table.rows
                    ##data=sorted(table.rows,
                    ##          key=operator.attrgetter('begin_ts'),
                    ##          reverse=False)
                )
                #graph.print_graph()
                ####
                #print(line_format.format(tid, query_duration, user, db, ret, query_name.replace(os.linesep, ' ')))
            #proc_total_calls = total_row.count.value
            graph.print_graph()
            #print('-' * 113)
            #print(line_format.format('Total:', proc_total_calls,
            print(line_format.format('Total:', proc_total_calls,
                                     '', '', '', '', ''))
            print('-' * 113)
            total_calls += proc_total_calls

        print('\nTotal queries: %d' % (total_calls))



    def _print_per_dbtable_summary_results(self, total_table, per_dbtable_tables):
        line_format = '{:<38} {:>14} {:>14} {:>14} {:>12} {:>10}  {:<14}'

        print('Per-(db,table) query statistics (usec)')
        total_calls = 0

        for total_row, table in zip(total_table.rows, per_dbtable_tables):
            print(line_format.format(table.subtitle,
                                     'Count', 'Min', 'Average', 'Max',
                                     'Stdev', 'Return values'))
            for row in table.rows:
                query_name = row.query.name
                query_count = row.count.value
                min_duration = round(row.min_duration.to_us(), 3)
                avg_duration = round(row.avg_duration.to_us(), 3)
                max_duration = round(row.max_duration.to_us(), 3)

                if type(row.stdev_duration) is mi.Unknown:
                    stdev = '?'
                else:
                    stdev = round(row.stdev_duration.to_us(), 3)

                proc_total_calls = total_row.count.value
                print(line_format.format(
                    ' - ' + query_name, query_count, min_duration,
                    avg_duration, max_duration, stdev,
                    row.return_values.value))

            print(line_format.format('Total:', proc_total_calls,
                                     '', '', '', '', ''))
            print('-' * 113)
            total_calls += proc_total_calls

        print('\nTotal queries: %d' % (total_calls))
        print('-' * 113)

    def _print_per_tid_summary_results(self, total_table, per_tid_tables):
        line_format = '{:<38} {:>14} {:>14} {:>14} {:>12} {:>10}  {:<14}'

        print('Per-TID mysql query statistics (usec)')
        total_calls = 0

        for total_row, table in zip(total_table.rows, per_tid_tables):
            print(line_format.format(table.subtitle,
                                     'Count', 'Min', 'Average', 'Max',
                                     'Stdev', 'Return values'))
            for row in table.rows:
                query_name = row.query.name
                query_count = row.count.value
                min_duration = round(row.min_duration.to_us(), 3)
                avg_duration = round(row.avg_duration.to_us(), 3)
                max_duration = round(row.max_duration.to_us(), 3)

                if type(row.stdev_duration) is mi.Unknown:
                    stdev = '?'
                else:
                    stdev = round(row.stdev_duration.to_us(), 3)

                proc_total_calls = total_row.count.value
                print(line_format.format(
                    ' - ' + query_name, query_count, min_duration,
                    avg_duration, max_duration, stdev,
                    row.return_values.value))

            print(line_format.format('Total:', proc_total_calls,
                                     '', '', '', '', ''))
            print('-' * 113)
            total_calls += proc_total_calls

        print('\nTotal queries: %d' % (total_calls))
        print('-' * 113)

    def _add_arguments(self, ap):
        Command._add_proc_filter_args(ap)


def _run(mi_mode):
    syscallscmd = MYSQLAnalysis(mi_mode=mi_mode)
    syscallscmd.run()


# entry point (human)
def run():
    _run(mi_mode=False)
    #_run(mi_mode=True)


# entry point (MI)
def run_mi():
    _run(mi_mode=True)
