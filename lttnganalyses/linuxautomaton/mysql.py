# The MIT License (MIT)
#
# Copyright (C) 2015 - Julien Desfossez <jdesfossez@efficios.com>
#               2015 - Antoine Busque <abusque@efficios.com>
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

from . import sp, sv
import os


class MysqlStateProvider(sp.StateProvider):
    def __init__(self, state):
        cbs = {

            'ust_mysql:query_start': self._mysql_query_start,
            'ust_mysql:query_done': self._mysql_query_done,
            'ust_mysql:connection_start': self._mysql_connection_start,
            'ust_mysql:connection_done': self._mysql_connection_done,
            'ust_mysql:command_start': self._mysql_command_start,
            'ust_mysql:command_done': self._mysql_command_done,


        }

        super().__init__(state, cbs)

    def _mysql_query_start(self, event):
        self._state.send_notification_cb('ust_mysql:query_start',
                                         query=event['query'],
                                         thread_id=event['thread_id'],
                                         db=event['db'],
                                         host_or_ip=event['host_or_ip'],
                                         priv_user=event['priv_user'],
                                         cpu_id=event['cpu_id']
                                         )
        queryname = event['query']
        id = event['thread_id']
        db = event['db']
        host_or_ip = event['host_or_ip']
        priv_user = event['priv_user']
        cpu_id = event['cpu_id']
        query = sv.MysqlQuery(id, db, priv_user, queryname, event.timestamp)
        self._state.mysqlqueries[id] = query

    def _mysql_query_done(self, event):
        cpu_id = event['cpu_id']
        id = event['thread_id']
        result = event['result']
        sqlQuery =  self._state.mysqlqueries[id]

        if sqlQuery:
            duration = event.timestamp - sqlQuery.begin_ts
            sqlQuery.query_exit(event)
            connection = self._state.mysqlconnections[id]
            if connection is not None:
                connection.update_duration(duration)
            self._state.send_notification_cb('ust_mysql:query_done',
                                             result=event['result'],
                                             duration=duration,
                                             thread_id=id,
                                             query = sqlQuery,
                                             connection=self._state.mysqlconnections[id],
                                             cpu_id=event['cpu_id'])

            self._state.mysqlqueries[id] = None

        else:
            print('------ ERROR: No such open sql connection running in cpu %s.' % (cpu_id))

        output = 'tid: %s: query: %s  result: %s duration: %d (ns)' % (id, sqlQuery.query.replace(os.linesep, ' '),  result, duration)
        #print (output)
        #print('<<- ' + method + " " + uri)

    def _mysql_connection_start(self, event):
        id = event['thread_id']
        #db = event['db']
        host_or_ip = event['host_or_ip_field']
        priv_user = event['priv_user']
        cpu_id = event['cpu_id']
        self._state.mysqlconnections[id] = sv.MysqlConnection(id, priv_user, host_or_ip, event.timestamp)
        #print('->>>starting a mysql connection: %d' %  (id))

    def _mysql_connection_done(self, event):
        id = event['thread_id']
        result = event['result']
        cpu_id = event['cpu_id']
        self._state.mysqlqueries[id] = None
        mysqlConn =  self._state.mysqlconnections[id]
        duration = 0
        queryduration = 0
        if mysqlConn:
            mysqlConn.connection_exit(event)
            duration = mysqlConn.duration
            queryduration = mysqlConn.queryduration

        #print('<<<- closing mysql connection: %d. total duration: %d, queries duration: %d' % (id, duration, queryduration))

    def _mysql_command_start(self, event):
        id = event['thread_id']
        command = event['command']

        # db = event['db']
        host_or_ip = event['host_or_ip']
        priv_user = event['priv_user']
        cpu_id = event['cpu_id']

        #print('->>cpu: %d  thread_id: %d command: %d' % (cpu_id, id, command))

    def _mysql_command_done(self, event):
        result = event['result']
        cpu_id = event['cpu_id']
        id = event['thread_id']

        #print('<<- cpu: %d thread_id %d result: %d' % (cpu_id, id, result))