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

class PHPAnalysis(Command):
    _DESC = """The phptop command."""
    _ANALYSIS_CLASS = phptop.PHPAnalysis
    _MI_TITLE = 'Php requests statistics'
    _MI_DESCRIPTION = 'PHP requests statistics'
    _MI_TAGS = [mi.Tags.PHP, mi.Tags.MYSQL]
    _MI_TABLE_CLASS_TOTAL = 'total'
    _MI_TABLE_CLASS_TOTAL_APACHE = 'total apache'
    _MI_TABLE_CLASSES = [
        (
            _MI_TABLE_CLASS_TOTAL,
            'PHP requests statistics', [
                ('tid', 'Request ID', mi.Number),
                ('duration', 'Duration', mi.Duration, 'usec'),
                ('sqlduration', 'DB Execution Duration', mi.Duration, 'usec'),
                ('sqlthreadid', 'DB Connection IDs', mi.Number),
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
                ('sqlduration', 'DB Execution Duration', mi.Duration, 'usec'),
                ('sqlthreadid', 'DB Connection IDs', mi.Number),
                ('uri', 'Uri', mi.String),
                ('path', 'File Path', mi.String),
                ('method', 'Method', mi.String),
                ('durationlong', 'Duration long', mi.Number),
                ('begin_ts', 'Starting timestamp', mi.Number),
                ('end_ts', 'Ending timestamp', mi.Number),
            ]
        ),
    ]

    def _analysis_tick(self, begin_ns, end_ns):
        total_requests__table = self._get_per_tid_queries_tables(begin_ns, end_ns)
        apache_total_requests__table = self._get_apache_per_tid_queries_tables(begin_ns, end_ns)

        #self._get_querytypes_per_dbtable_tables(begin_ns, end_ns)

        if self._mi_mode:
            self._mi_append_result_tables(total_requests__table)
        else:
            self._print_date(begin_ns, end_ns)
            self._print_apacherequests_summary(apache_total_requests__table)
            self._print_requests_summary(total_requests__table)

    def _post_analysis(self):
        if not self._mi_mode:
            return

        if len(self._mi_get_querytypes_per_tid_tables(self._MI_TABLE_CLASS_TOTAL)) > 1:
            self._create_summary_result_table()

        self._mi_print()

    def _get_per_tid_queries_tables(self, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        for requests in sorted(self._analysis.requests.values(),
                                 key=operator.attrgetter('count'),
                                 reverse=False):
            if requests.total_requests == 0:
                continue
            count = 0

            for req in requests.request_list:
                #if (req.mysql_threadid is None) or len(req.mysql_threadid <= 0):
                mysql_threadid = ''
                if not req.mysql_threadid:
                    mysql_threadid = ",".join(map(str, req.mysql_threadid))

                total_table.append_row(
                    tid=mi.Number(req.id),
                    duration=mi.Duration(req.duration),
                    sqlduration=mi.Duration(req.mysql_duration),
                    sqlthreadid=mi.String(mysql_threadid),
                    uri=mi.String(req.uri),
                    path=mi.String(req.path),
                    method=mi.String(req.method),
                    durationlong=req.duration,
                    begin_ts=req.begin_ts,
                    end_ts = req.end_ts
                )
                count += 1

        return total_table

    def _get_apache_per_tid_queries_tables(self, begin_ns, end_ns):
        per_tid_tables = []
        total_table = self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                                   begin_ns, end_ns)

        for requests in sorted(self._analysis.apacherequests.values(),
                               key=operator.attrgetter('count'),
                               reverse=False):
            if requests.total_requests == 0:
                continue
            count = 0

            for req in requests.request_list:
                # if (req.mysql_threadid is None) or len(req.mysql_threadid <= 0):
                mysql_threadid = ''
                if not req.mysql_threadid:
                    mysql_threadid = ",".join(map(str, req.mysql_threadid))

                total_table.append_row(
                    tid=mi.Number(req.id),
                    duration=mi.Duration(req.duration),
                    sqlduration=mi.Duration(req.mysql_duration),
                    sqlthreadid=mi.String(mysql_threadid),
                    uri=mi.String(req.uri),
                    path=mi.String(req.path),
                    method=mi.String(req.method),
                    durationlong=req.duration,
                    begin_ts=req.begin_ts,
                    end_ts=req.end_ts
                )
                count += 1

        return total_table

    def _print_requests_summary(self, total_table):
        line_format = '{:<10} {:<10} {}'

        print('PHP requests details:')
        total_requests = 0

        for row in total_table.rows:
            tid = row.tid.value
            duration = row.duration.to_us()
            sqlduration = row.duration.to_us()
            method = row.method.value
            uri = row.uri.value
            path = row.path.value
            mysql_threadid = row.sqlthreadid.value

            row_format = '  {:<10} {:>10} {:>10}  {:>10} {}'
            #row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
            label_header = row_format.format('SQL duration', 'Method', 'URI', 'PATH', 'SQL Connection ID(s)')

            def format_label(row):
                return row_format.format(
                    # row.duration.to_us(),
                    # row.user.value,
                    #'%.4f (%.2f %)'% (str(row.sqlduration.to_us()) + '('+ str((row.sqlduration.to_us()*100)/row.duration.to_us()) + '%)',
                    '%0.02f (%0.02f %%)' %(row.sqlduration.to_us(),(row.sqlduration.to_us() * 100) / row.duration.to_us()),
                    #row.sqlduration.to_us(),
                    row.method.value,
                    row.uri.value,
                    row.path.value,
                    row.sqlthreadid.value
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

    def _print_apacherequests_summary(self, total_table):
        line_format = '{:<10} {:<10} {}'

        print('Apache requests details:')
        total_requests = 0

        for row in total_table.rows:
            tid = row.tid.value
            duration = row.duration.to_us()
            sqlduration = row.duration.to_us()
            method = row.method.value
            uri = row.uri.value
            path = row.path.value
            mysql_threadid = row.sqlthreadid.value

            row_format = '  {:<10} {}'
            # row_format = '  {:<10} {:>10} {:>10}  {:>10} {:<10}'
            label_header = row_format.format('Method', 'URI')

            def format_label(row):
                return row_format.format(
                    # row.duration.to_us(),
                    # row.user.value,
                    # '%.4f (%.2f %)'% (str(row.sqlduration.to_us()) + '('+ str((row.sqlduration.to_us()*100)/row.duration.to_us()) + '%)',
                    #'%0.02f (%0.02f %%)' % (
                    #row.sqlduration.to_us(), (row.sqlduration.to_us() * 100) / row.duration.to_us()),
                    # row.sqlduration.to_us(),
                    row.method.value,
                    '%s%s'%(row.path.value, row.uri.value),

                    #row.sqlthreadid.value
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

    def _add_arguments(self, ap):
        Command._add_proc_filter_args(ap)


def _run(mi_mode):
    syscallscmd = PHPAnalysis(mi_mode=mi_mode)
    syscallscmd.run()


# entry point (human)
def run():
    _run(mi_mode=False)


# entry point (MI)
def run_mi():
    _run(mi_mode=True)
