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
import json

class PhpStateProvider(sp.StateProvider):
    def __init__(self, state):
        cbs = {
            'ust_php:request_entry': self._php_request_entry,
            'ust_php:request_exit': self._php_request_exit,
            'ust_php:function_entry': self._php_function_entry,
            'ust_php:function_exit': self._php_function_exit,
        }

        super().__init__(state, cbs)
        self.id = 1
        self.last_read = 1
        self.indent = 0
        self.requestsstatus = {}

    def _php_request_entry(self, event):
        cpu_id = event['cpu_id']
        method = event['method']
        path = event['path']
        uri = event['uri']
        #querystring = ''
        #querystring = ''
        if event['querystring'] is not None:
            querystring = event['querystring']
        else:
            querystring = None

        if event['_vtid'] is not None:
            id = event['_vtid']
        else:
            print ('error: you should enable vtid in lttng ')
            return

        if id not in self.requestsstatus:
            self.requestsstatus[id] = 0


        self._state.phprequests[id] =sv.PhpRequest(id, method, event.timestamp,  path, uri, querystring, cpu_id)

        apacherequest = self._state.apacherequests[id]
        if apacherequest is not None:
            apacherequest.update_phpid(id)
        #print('----------------------->>  cpu ' + str(cpu_id) + ":" +str(self.id)+ ": " +method + " " + uri+"?"+querystring)

        self.id += 1

    def _php_request_exit(self, event):
        cpu_id = event['cpu_id']
        method = event['method']
        path = event['path']
        uri = event['uri']
        #querystring = ''
        #querystring = None
        if event['querystring'] is not None:
            querystring = event['querystring']
        else:
            querystring = None
        #querystring = event['querystring']
        selected_request = None
        if event['_vtid'] is not None:
            id = event['_vtid']
        else:
            #print('error: you should enable vtid in lttng ')
            return

        if id in self.requestsstatus:
            self.requestsstatus[id] = 0

        request = self._state.phprequests[id]
        if request is None:
            return

        request.request_exit(event)
        mysqlduration = 0
        querycount = 0
        if request.mysql_threadid is not None:
            for mysql_tid in request.mysql_threadid:
                connection = self._state.mysqlconnections[mysql_tid]
                if connection is not None:
                    mysqlduration += connection.queryduration
                    querycount += connection.querycount

        request.update_mysqlduration(mysqlduration, querycount)

        duration = event.timestamp - request.begin_ts

        apacherequest = self._state.apacherequests[id]
        if apacherequest is not None:
            apacherequest.update_phpduration(duration)
            apacherequest.update_mysqlduration(mysqlduration, querycount)

        self._state.send_notification_cb('ust_php:request_exit',
                                         method=event['method'],
                                         path=event['path'],
                                         uri=event['uri'],
                                         request = request,
                                         duration = duration,
                                         id=event['_vtid'],
                                         cpu_id=event['cpu_id']
                                         )

    def _php_function_entry(self, event):
        emptyfunctionlists = []
        cpu_id = event['cpu_id']
        filename = event['filename']
        funcname = event['funcname']
        lineno = event['lineno']
        classname = event['class_name']
        if event['_vtid'] is not None:
            id = event['_vtid']
        else:
            return

        if id in self.requestsstatus:
            self.requestsstatus[id] += 1
        else:
            self.requestsstatus[id] = 1
            #self.requestsstatus[id] = 0

        if id not in  self._state.phpfunctions:
            self._state.phpfunctions[id] = emptyfunctionlists

        functionlists = self._state.phpfunctions[id]
        functionlists.append(sv.PhpFunction(id, funcname, filename, classname, lineno, event.timestamp, self.requestsstatus[id]))

        self.indent += 2
        indent = ''
        for x in range(0, self.indent):
            indent += ' '
        output = '%s ->%s: function %s+%s ' % (indent, self.id, funcname,lineno)
        #print(output)

    def _php_function_exit(self, event):
        cpu_id = event['cpu_id']
        filename = event['filename']
        funcname = event['funcname']
        lineno = event['lineno']
        if event['_vtid'] is not None:
            id = event['_vtid']
        else:
            return

        if id in self.requestsstatus:
            self.requestsstatus[id] -= 1
            if self.requestsstatus[id] < 0:
                self.requestsstatus[id] = 0
        else:
            self.requestsstatus[id] = 0

        selected_function = None
        functions = self._state.phpfunctions[id]
        for function in functions:
            if function.name == funcname and function.filename == filename and  function.lineno == lineno:
                selected_function = function
                self._state.phpfunctions[id].remove(selected_function)
                break


        if selected_function is None or selected_function.begin_ts is None:
            #self.indent -= 2
            return

        duration = event.timestamp - selected_function.begin_ts
        selected_function.function_exit(event)
        self._state.send_notification_cb('ust_php:function_exit',
                                         cpu_id=event['cpu_id'],
                                         funcname=event['funcname'],
                                         filename=event['filename'],
                                         classname=event['class_name'],
                                         lineno=event['lineno'],
                                         id = id,
                                         duration=duration,
                                         function = selected_function
                                         )
        indent = ''
        for x in range(0, self.indent):
            indent += ' '
        output = '%s <-%s: function %s+%s  (%d ns)' % (indent, self.id, funcname, lineno, duration)
        #print(output)
        self.indent -= 2


    def _apache_module_entry(self, event):
        cpu_id = event['cpu_id']
        name = event['name']
        if name == 'process_connection':
            print('--> process_connection')
        if name == 'suspend_connection':
           print('<-- suspend_connection')


        #self._state.phprequests[self.id] = sv.PhpRequest(self.id, method, event.timestamp, path, uri)
        # print('----------------------->>  ' + str(self.id)+ ": " +method + " " + uri)

    def _apache_request_info(self, event):
        cpu_id = event['cpu_id']
        connection_id = event['id']
        method = event['method']
        uri = event['uri']

        print('%s: %s %s'%(connection_id, method, uri))

    def _apache_request_entry(self, event):
        id = event['id']
        method = event['method']
        uri = event['uri']
        host = event['client_ip']
        cpu_id = event['cpu_id']

        apacherequest = sv.ApacheRequest(id, method, event.timestamp, host, uri, '', cpu_id)
        self._state.apacherequests[id] = apacherequest

        #output = '>> tid: %s: %s %s%s' % (
        #    id, apacherequest.method, apacherequest.host, apacherequest.uri )
        #print(output)

    def _apache_request_exit(self, event):
        id = event['id']
        status = event['status']
        cpu_id = event['cpu_id']
        if id not in self._state.apacherequests:
            return

        apacherequest = self._state.apacherequests[id]
        if apacherequest is None:
            return

        duration = event.timestamp - apacherequest.begin_ts
        apacherequest.request_exit(event)

        self._state.send_notification_cb('ust_apache:request_exit',
                                         method=apacherequest.method,
                                         host=apacherequest.host,
                                         uri=apacherequest.uri,
                                         request=apacherequest,
                                         duration=duration,
                                         id=id,
                                         cpu_id=event['cpu_id'])

        self._state.apacherequests[id] = None



        #output = '<< tid: %s: %s %s%s duration: %d (ns)' % (
        #id, apacherequest.method, apacherequest.host, apacherequest.uri, duration)
        #print (output)
        # print('<<- ' + method + " " + uri)
