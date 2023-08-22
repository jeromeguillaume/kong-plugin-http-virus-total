# Kong plugin: detect a malware in the request Body by using [VirusTotal (VT)](https://virustotal.com) REST API

The VirusTotal parameters are:
- `virustotal_endpoint_to_upload_file`: VirusTotal Endpoint to upload the file to analyze
- `virustotal_malicious_percentage_threshold`: the threshold of malicious percentage to establish that a file has a malware (VirtusTotal has many sources and some sources say that there is a malware and other sources say that there is no malware)
- `virustotal_retries_nb`: number of retries to call VT `/analyses` API. Once the VT Upload API is called the plugin calls the VT `/analyses` API until `data.attributes.status` is `completed`or the plugin reaches the value
- `virustotal_retries_sleep`: duration (in second) to sleep between each retry
- `virustotal_x_apikey`: x-apikey value provided by VT

The proxy parameters are:
- `http_proxy`: an URI to a proxy server to be used with HTTP requests
- `http_proxy_authorization`: a default Proxy-Authorization header value to be used with http_proxy, e.g. Basic ZGVtbzp0ZXN0, which will be overriden if the Proxy-Authorization request header is present.
- `https_proxy`: an URI to a proxy server to be used with HTTPS requests
- `https_proxy_authorization`: as http_proxy_authorization but for use with https_proxy (since with HTTPS the authorisation is done when connecting, this one cannot be overridden by passing the Proxy-Authorization request header).
- `no_proxy`: a comma separated list of hosts that should not be proxied.
 

 http -v -f POST https://www.virustotal.com/api/v3/files x-apikey:10f691334364c4da44dd3899c886ecae9310d1a17293f7b1ea854218c2255aff file@'./virus/eicar.com'   