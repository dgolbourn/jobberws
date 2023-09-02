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


local result = jobberws.query("SELECT * FROM Person")
jobberws.log("query returned " .. #result .. " rows")
for i = 1,#result,1 do
    jobberws.log(result[i].name)
end

--create an html response here
jobberws.log("response")

local response = jobberws.response()
response.status = 200
response.response = "<html><body>200 OK</body></html>"
response:send()