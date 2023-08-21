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
          { http_proxy = typedefs.url {required = false,},},
          { http_proxy_authorization = { required = false, type = "string",},},
          { https_proxy = typedefs.url {required = false,},},
          { https_proxy_authorization = { required = false, type = "string",},},
          { no_proxy = { required = false, type = "string",},},
        },
      },
    },
  },
}