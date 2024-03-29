JobberWS Documentation
======================
This is the documentation for JobberWS 0.1

Introduction
============
JobberWS is a web server written in C. It is designed to allow you create restful web services by extending the web server using Lua.

How to use
==========
JobberWS is run on the command line like

::

    jobberws scripts/config.json


The config file is described by the following template

.. code-block:: js

    {
        "database" : {
            "user" : string,
            "password" : string,
            "host" : string /*optional*/,
            "database" : string /*optional*/,
            "socket" : string /*optional*/,
            "port" : integer /*optional*/
        },
        "webservice" : {
            "port" : integer,
            "filename" : string,
            "preload" : /*optional*/ {
                "libraryName1" : "library1.lua",
                "libraryName2" : "library2.lua",
                ...
            },
            "https" : /*optional*/ {
                "key" : string,
                "cert" : string
            }
        }
    }


``"database"``

This object contains the configuration for the mySql database to connect to. `"username"` and `"password"` are mandatory, other fields will be defaulted.

``"webservice"``

This object contains the configuration of the web service you have created.

    ``"port"`` is the port that this web service is served on.

    ``"filename"`` is the name of the main lua script to run that represents the webservice. This is precompiled as bytecode and the bytecode is loaded each time a connection is made.

    ``"preload"`` is a list of other lua scripts to pre-compile as bytecode. The bytecode is then loaded when these libraries are imported by the main script via ``require``.

    ``"https"`` is an object that if included contains the filename of the key and certificate to activate https on this webservice.

Anatomy of the webservice
=========================
Each time a new connection is made the lua bytecode for the service is executed. This will run as a separate lua state on a separate execution thread.

The lua thread will be called once when the connection is created. It will then be called multiple further times with upload data if present. It will then be called one last time where a response message should be generated by the script.

Each time, the script may do processing after which it should return control to the webserver by calling ``yield()``. If the script ends without calling ``yield()``, the script will be run again from the start instead of resuming from the yield site.

Example
-------

.. code-block:: lua

    local jobberws = require "jobberws"

    --do validation here. E.g username, url, connection data etc.
    jobberws.log("validate")

    --yield once validation is done
    jobberws.yield()

    local data = jobberws.upload_data()
    --if there is data then process it
    while data do
        --process upload data in chunks here
        jobberws.log("processing upload data " .. #data .. " bytes")
        --yield after each chunk of data
        jobberws.yield()
        data = jobberws.upload_data()
    end

    --create an html response here
    jobberws.log("response")

    local response = jobberws.response()
    response.status = 200
    response.response = "<html><body>200 OK</body></html>"
    response:send()



lua API Reference
=================

Packages
--------

``jobberws``
++++++++++++

The ``jobberws`` package is available as

.. code-block:: lua

    local jobberws = require "jobberws"


The table returned has the following entries

.. function:: query(qry)

    make an SQL query. Rows are returned as an ``sql result``

    :param qry: the query
    :type qry: string
    :rtype: ``sql result``

.. code-block:: lua

    --log all rows from the query
    local result = jobberws.query("SELECT * FROM person")
    jobberws.log("query returned " .. #result .. " rows")
    for i = 1,#result,1 do
        jobberws.log(result[i].name)
    end

.. function:: json_to_lua(json)

    convert a string of json data into a lua table

    :param json: the json string
    :type json: string

    :rtype: table

.. code-block:: lua

    --convert the json string to a lua table
    jobberws.log(jobberws.json_to_lua("{\"key\" : \"value\"}").key)


.. function:: lua_to_json(table)

    convert a lua table to a json formatted string

    :param table: the table
    :type table: table

    :rtype: string

.. code-block:: lua

    --convert a lua list to json
    jobberws.log(jobberws.lua_to_json({"egg", "fish", "banana"}))

    --convert a lua table to json
    local t = {
        eat = "no",
        drink = "yes"
    }
    jobberws.log(jobberws.lua_to_json(t))


.. data:: url

    the connection url

    :type: string

.. data:: method

    the connection method

    :type: string

.. data:: version

    the connection version

    :type: string

.. data:: password

    the connection basic auth password

    :type: string

.. data:: username

    the connection basic auth username

    :type: string

.. code-block:: lua

    --check the username and queue a response
    if jobberws.username ~= "test" then
        local response = jobberws.response()
        response.response = "<html><body>unknown user</body></html>"
        response.realm = "jobberws"
        response:send()
        return
    end


.. function:: post_processor()

    a post processor to use to consume post data

    :rtype: ``post processor``

.. function:: values(kind, key)

    get connection values.  If key is nil returns a table of key value pairs, else returns value as string

    :param kind: the kind of values
    :type kind: integer
    :param key: the key
    :type key: string
    :rtype: table or string

.. code-block:: lua

    --get values of a certain kind
    for k,v in pairs(jobberws.values(8)) do
        jobberws.log(k .. " : " .. v)
    end

    --get a specific key of a certain kind
    jobberws.log(jobberws.values(8, "r"))


.. function:: upload_data()

    get the current upload data

    :rtype: string

.. function:: yield()

    yield control back to the webserver

    :rtype: none

.. function:: response()

    create a response object

    :rtype: ``response``

.. function:: crypt(key, salt)

    sha256 crypt function

    :param key: the user's password (up to 256 chars)
    :type key: string
    :param salt: setting in format ``$5$rounds=n$salt$``. ``rounds=n$`` and closing ``$`` are optional. ``salt`` is up to 16 chars. ``rounds`` defaults to 5000.
    :type salt: string

    return is formatted as ``$5$rounds=n$salt$hash``

    :rtype: string

.. function:: base64_to_raw(str)

    convert a base64 formatted string into raw bytes

    :param str: string to convert
    :type key: string
    :rtype: string

.. function:: raw_to_base64(str)

    convert a raw sring of bytes into base64 encoding

    :param str: string to convert
    :type key: string
    :rtype: string

.. data:: log

    set or get the logging function. This defaults to the ``stderr`` logger

    :rtype: ``logger``

Types
-----

``logger``
++++++++++

.. function:: logger(message)

    log a message

    :param message: a message to log
    :type message: string
    :rtype: none

.. code-block:: lua

    --set the logger
    jobberws.log = print
    jobberws.log("log to the lua print function (stdout)")


``response``
++++++++++++

The ``response`` table returned from calling ``jobberws.response()`` has the following functions and data

.. data:: status

    set the status

    :type: string

.. data:: realm

    set the realm

    :type: string

.. data:: response

    set the response

    :type: string

.. data:: header

    set the header

    :type: string

.. function:: send(self)

    send the response

    :param self: this response
    :type self: response
    :rtype: none

``post processor``
++++++++++++++++++

The ``post processor`` returned from calling ``jobberws.post_processor()`` has the following function

.. function:: __call(self, data)

    consume the post data and return any new key value pairs that have been fully decoded

    :param self: this post processor
    :type self: post processor
    :param data: the post data
    :type data: string
    :rtype: table

``sql result``
++++++++++++++

The ``sql result`` returned from calling ``jobberws.query()`` has the following functions

.. function:: __index(self, index)

    fetch the row at the given index

    :param self: this sql result
    :type self: sql result
    :param index: the row index
    :type index: integer
    :rtype: ``sql row``

.. function:: __len(self)

    get the number of rows in this result

    :param self: this sql result
    :type self: sql result
    :rtype: integer

``sql row``
+++++++++++

``sql row`` has the following function

.. function:: __index(self, field)

    fetch the given field from the row

    :param self: this sql row
    :type self: sql row
    :param field: if a string then this is the field name, if an integer then this is the column number
    :type field: integer or string
    :rtype: string or empty table if not present


License
=======

Copyright (c) 2023 Diane Marigold

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
