# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903513");
  script_version("2021-08-04T10:08:11+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-08-04 10:08:11 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"creation_date", value:"2014-02-25 13:05:23 +0530 (Tue, 25 Feb 2014)");
  script_name("Zen-cart E-commerce Multiple Vulnerabilities Feb-2014");

  script_tag(name:"summary", value:"The host is running Zen-cart and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw are due to an,

  - Error which fails to sanitize 'redirect' parameter properly.

  - Insufficient validation of user-supplied input via the multiple POST
  parameters to multiple pages.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site and also can conduct phishing attacks.");

  script_tag(name:"affected", value:"Zen-cart version 1.5.1.");

  script_tag(name:"solution", value:"Vendor fixes are available.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125383/zencart151-shellxss.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/zen-cart-e-commerce-151-xss-open-redirect-shell-upload");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

zcPort = http_get_port(default:80);

if(!http_can_host_php(port:zcPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/zencart", "/cart", http_cgi_dirs(port:zcPort)))
{

  if(dir == "/") dir = "";

  zenRes = http_get_cache(item:string(dir, "/index.php"), port:zcPort);

  if(zenRes && (egrep(pattern:"Powered by.*Zen Cart<", string:zenRes)))
  {
    url = dir + "/index.php?main_page=redirect&action=url&goto=www." +
            "example.com" ;
    ##Send the exploit
    zenReq = http_get(item:url, port:zcPort);
    zenRes = http_keepalive_send_recv(port:zcPort, data:zenReq, bodyonly:FALSE);

    if(zenRes && zenRes =~ "HTTP/1.. 302" && "Location: http://www.example.com" >< zenRes)
    {
      security_message(port:zcPort);
      exit(0);
    }
  }
}

exit(99);
