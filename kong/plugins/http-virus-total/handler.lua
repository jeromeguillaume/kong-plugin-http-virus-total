local http = require "resty.http"
local fmt = string.format
  
local HttpVirusTotal = {
  PRIORITY = 2002,
  VERSION = '1.0.0',
}

---------------------------------------------------------------------------------------------------
-- Executed for every request from a client and before it is being proxied to the upstream service
---------------------------------------------------------------------------------------------------
function HttpVirusTotal:access(conf)
  
  local request_body = kong.request.get_raw_body()
  
  -- If the body is empty
  if request_body == '' then
    kong.log.notice("There is no body to analyze with VirusTotal")
    return
  end

  -- Else if the Content-Type doesn't speciy  a File upload
  local i, _ = string.find(kong.request.get_header('Content-Type'), 'multipart%/form%-data')
  
  if i ~= 1 then
    kong.log.notice("The MIME type doesn't start by 'multipart/form-data' (we found: '" .. kong.request.get_header('content-type') .. "'). There is no file to analyze with VirusTotal")
    return
  end

kong.log.notice("JEROME: request_body: '" .. request_body .. "'")

  local httpc = http.new()

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
  
  local headers = {
    ["Accept"] = "application/json",
    ["Content-Type"] = kong.request.get_header('Content-Type'),
    ["x-apikey"] = conf.virustotal_x_apikey,
  }

  -- FIRSTLY, Upload the file to Virus Total - API
  local res, err = httpc:request_uri(conf.virustotal_endpoint_to_upload_file, {
    method = "POST",
    headers = headers,
    body = request_body,
    keepalive_timeout = 60,
    keepalive_pool = 10
  })
  if not res then
    return nil, "Failed to upload the file to Virus Total '" .. conf.virustotal_endpoint_to_upload_file .. "': " .. err
  end

  local response_body = res.body

  kong.log.notice(fmt("Upload the file to Virus Total '%s' | HTTP status: %d | body: %s",
  conf.virustotal_endpoint_to_upload_file, tostring(res.status), response_body ))

  if res.status >= 300 then
    return nil, "Failed to upload the file to Virus Total '" .. conf.virustotal_endpoint_to_upload_file .. "' HTTP status: " .. tostring(res.status)
  end

  local cjson = require("cjson.safe").new()
  local dataVT, err = cjson.decode(response_body)
  -- If we failed to base64 decode
  if err then
    kong.log.err ("Failure to json decode payload")
    return nil, "Failure to json decode payload"
  end
  if not (dataVT.data and dataVT.data.links and dataVT.data.links.self) then
    kong.log.err ("Failure to get 'data.links.self' for file Analysis on Virus Total")
    return nil, "Failure to get 'data.links.self' for file Analysis on Virus Total"
  end

  -- SECONDLY, Analyze the file on Virus Total - API
  local headers = {
    ["Accept"] = "application/json",
    ["x-apikey"] = conf.virustotal_x_apikey,
  }
  local res, err = httpc:request_uri(dataVT.data.links.self, {
    method = "GET",
    headers = headers,
    keepalive_timeout = 60,
    keepalive_pool = 10
  })
  if not res then
    return nil, "Failed to analyze the file on Virus Total '" .. dataVT.data.links.self .. "': " .. err
  end

  kong.log.notice(fmt("Analyze the file from Virus Total '%s' | HTTP status: %d | body: %s",
  dataVT.data.links.self, tostring(res.status), res.body ))


end

return HttpVirusTotal