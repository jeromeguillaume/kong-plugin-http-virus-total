local typedefs = require "kong.db.schema.typedefs"
local url = require "socket.url"

return {
  name = "http-virus-total",
  fields = {
    { protocols = typedefs.protocols },
    { config = {
        type = "record",
        fields = {
          { virustotal_endpoint_to_upload_file = typedefs.url({ required = true, default = "https://www.virustotal.com/api/v3/files"}), },
          { virustotal_x_apikey = { required = true, type = "string", encrypted = true,},},
          { virustotal_malicious_percentage_threshold = { required = true, type = "integer", default = 5,},},
          { virustotal_retries_nb = { required = true, type = "integer", default = 10,},},
          { virustotal_retries_sleep = { required = true, type = "number", default = 0.250,},},
          { http_proxy = typedefs.url {required = false,},},
          { http_proxy_authorization = { required = false, type = "string",},},
          { https_proxy = typedefs.url {required = false,},},
          { https_proxy_authorization = { required = false, type = "string",},},
          { no_proxy = { required = false, type = "string",},},
          { verbose_request = { required = true, type = "boolean", default = false},},
        },
      },
    },
  },
}