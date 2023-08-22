local http = require "resty.http"
local fmt = string.format
  
local HttpVirusTotal = {
  PRIORITY = 2002,
  VERSION = '1.0.0',
}

---------------------------
-- Return the table length
---------------------------
local function tableLength(T)
  local count = 0
  for _ in pairs(T) do count = count + 1 end
  return count
end

---------------------------------------------------------------------------------------------------
-- Executed for every request from a client and before it is being proxied to the upstream service
---------------------------------------------------------------------------------------------------
function HttpVirusTotal:access(conf)
  
  local errMsg = nil
  local dataUploadVT
  local dataAnalyzeVT
  local err
  local cjson
  local res
  local headers
  local httpc = http.new()
  local request_body = kong.request.get_raw_body()
  
  -- If the body is empty
  if request_body == nil or request_body == '' then
    errMsg = "There is no body to analyze with VirusTotal"
  else
    -- If the Content-Type doesn't speciy a File to upload
    local i, _ = string.find(kong.request.get_header('Content-Type'), 'multipart%/form%-data')
    if i ~= 1 then
      errMsg = "The MIME type doesn't start by 'multipart/form-data' (we found: '" .. kong.request.get_header('content-type') .. "'). There is no file to analyze with VirusTotal"
    end  
  end
  
  -- If there is no Error
  if not errMsg then
    
    -- Set the HTTP/HTTPS proxy
    if httpc.set_proxy_options and (conf.http_proxy or conf.https_proxy) then
      httpc:set_proxy_options({
        http_proxy                = conf.http_proxy,
        http_proxy_authorization  = conf.http_proxy_authorization,
        https_proxy               = conf.https_proxy,
        https_proxy_authorization = conf.https_proxy_authorization,
        no_proxy                  = conf.no_proxy,
      })
    end
    
    headers = {
      ["Accept"] = "application/json",
      ["Content-Type"] = kong.request.get_header('Content-Type'),
      ["x-apikey"] = conf.virustotal_x_apikey,
    }

    kong.log.notice(fmt("call VirusTotal Upload file | req: '%s'", conf.virustotal_endpoint_to_upload_file))

    -- FIRSTLY, Upload the file to VirusTotal - API
    res, err = httpc:request_uri(conf.virustotal_endpoint_to_upload_file, {
      method = "POST",
      headers = headers,
      body = request_body,
      keepalive_timeout = 60,
      keepalive_pool = 10
    })
    if not res then
      errMsg = "Failed to upload the file to VirusTotal | Req: '" .. conf.virustotal_endpoint_to_upload_file .. "' | Err: " .. err
    else
      local response_body = res.body
      kong.log.notice(fmt("resp: '%s'", response_body))
      
      if res.status >= 300 then
        errMsg = fmt("Failed to upload the file to VirusTotal | req: '%s' | HTTP status: %d | body: %s", conf.virustotal_endpoint_to_upload_file, tostring(res.status), response_body)
      else
        cjson = require("cjson.safe").new()
        dataUploadVT, err = cjson.decode(response_body)
        -- If we failed to base64 decode
        if err then
          errMsg = fmt("Failure to JSON decode payload of VirusTotal Analyze | req: '%s' | err: %s | HTTP status: %d | body: %s", 
                      conf.virustotal_endpoint_to_upload_file,
                      err,
                      res.status,
                      res.body)
        elseif not (dataUploadVT.data and dataUploadVT.data.links and dataUploadVT.data.links.self) then
          errMsg = fmt("Failed get 'data.links.self' for uploading the file on VirusTotal | req: '%s' | HTTP status: %d | body: %s", 
                  conf.virustotal_endpoint_to_upload_file,
                  res.status,
                  res.body)
        end
      end
    end
  end
  
  -- SECONDLY, Analyze the file on VirusTotal - API
  local nb = 0
  headers = {
    ["Accept"] = "application/json",
    ["x-apikey"] = conf.virustotal_x_apikey,
  }
  local completed = false

  while not errMsg and not completed do
    if nb <= conf.virustotal_retries_nb then

      if nb > 0 then
        kong.log.notice(fmt("Do a %ds sleep before calling VirusTotal Analyze file", conf.virustotal_retries_sleep))
        ngx.sleep(conf.virustotal_retries_sleep)
      end

      kong.log.notice(fmt("call VirusTotal Analyze file | count: %d/%d | req: '%s'", nb, conf.virustotal_retries_nb, dataUploadVT.data.links.self))

      res, err = httpc:request_uri(dataUploadVT.data.links.self, {
        method = "GET",
        headers = headers,
        keepalive_timeout = 60,
        keepalive_pool = 10
      })
      nb = nb + 1

      -- If there is an error during the call to VirusTotal
      if not res then
        errMsg = "Failed to analyze the file on VirusTotal | Req: '" .. dataUploadVT.data.links.self .. "' | Err: " .. err
      -- Else If there is an HTTP Error during the call to VirusTotal
      elseif res.status >= 300 then
        errMsg = fmt("Failed to analyze the file on VirusTotal | req: '%s' | HTTP status: %d | body: %s", 
                      dataUploadVT.data.links.self,
                      res.status,
                      res.body)
      else
        kong.log.notice(fmt("resp: '%s'", res.body))
        dataAnalyzeVT, err = cjson.decode(res.body)
        -- If we failed to base64 decode
        if err then
          errMsg = fmt("Failure to JSON decode payload of VirusTotal Analyze | req: '%s' | err: %s | HTTP status: %d | body: %s", 
                        dataUploadVT.data.links.self,
                        err,
                        res.status,
                        res.body)
        else
          -- If we can't find the 'data.attributes.status' JSON property
          if not (dataAnalyzeVT.data and dataAnalyzeVT.data.attributes and dataAnalyzeVT.data.attributes.status) then
            errMsg = fmt("Failure to get 'data.attributes.status' for file Analysis on VirusTotal | req: '%s' | HTTP status: %d | body: %s", 
                          dataUploadVT.data.links.self,
                          res.status,
                          res.body)
          -- Else if the Analyze is completed
          elseif dataAnalyzeVT.data.attributes.status == 'completed' then
            -- If we can't find the 'data.attributes.stats.malicious' or 'data.attributes.results' JSON property
            if not (dataAnalyzeVT.data.attributes.stats and 
                    dataAnalyzeVT.data.attributes.stats.malicious and 
                    dataAnalyzeVT.data.attributes.results and 
                    tableLength(dataAnalyzeVT.data.attributes.results) ~= 0) then
              errMsg = fmt("Failure to get 'data.attributes.stats.malicious' or 'data.attributes.results' for file Analysis on VirusTotal | req: '%s' | HTTP status: %d | body: %s", 
                            dataUploadVT.data.links.self,
                            res.status,
                            res.body)
            else
              completed = true
            end
          end
        end
      end
    -- Maxixum number of retries is reached
    else
      errMsg = fmt("Failed to analyze the file on VirusTotal | req: '%s' | Reached the maximum number of tries: %d | HTTP status: %d | body: %s", 
                    dataUploadVT.data.links.self,
                    nb,
                    res.status,
                    res.body)
    end
  end

  local exitErr = {}
  if errMsg then
    kong.log.err(errMsg)
    exitErr["Error"] = "Unable to detect malware on the file"
    if conf.verbose_request then
      exitErr["Verbose Message"] = errMsg
    end
    kong.response.exit(500, exitErr, {["Content-Type"] = "application/json"})
  else
    -- Calculate the percentage of Malicious VT sources in comparison with the total of VT Sources
    local totalResultsVT = tonumber(tableLength(dataAnalyzeVT.data.attributes.results))
    if (tonumber(dataAnalyzeVT.data.attributes.stats.malicious) / totalResultsVT) * 100 >= tonumber(conf.virustotal_malicious_percentage_threshold) then
      errMsg = "The file has a malware"
      kong.log.err(errMsg)
      exitErr["Error"] = errMsg
      kong.response.exit(500, exitErr, {["Content-Type"] = "application/json"})
    end
  end
end

return HttpVirusTotal