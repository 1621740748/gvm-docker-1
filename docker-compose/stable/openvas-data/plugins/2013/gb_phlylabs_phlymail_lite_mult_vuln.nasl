###############################################################################
# OpenVAS Vulnerability Test
#
# phlyLabs phlyMail Lite Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803151");
  script_version("2020-08-24T15:18:35+0000");
  script_bugtraq_id(57303, 57304);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-01-15 12:12:35 +0530 (Tue, 15 Jan 2013)");
  script_name("phlyLabs phlyMail Lite Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24087");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24086");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013010113");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5122.php");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site
  and displaying the full webapp installation path.");

  script_tag(name:"affected", value:"phlyLabs phlyMail Lite version 4.03.04");

  script_tag(name:"insight", value:"- Input passed via the 'go' parameter in 'derefer.php' script is
  not properly verified before being used to redirect users. This can be
  exploited to redirect a user to an arbitrary website.

  - phlyMail suffers from multiple stored XSS vulnerabilities (post-auth)
  and path disclosure when input passed via several parameters to several
  scripts is not properly sanitized before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to phlyLabs phlyMail Lite version 4.3.57 or later.");

  script_tag(name:"summary", value:"This host is installed with phlyLabs phlyMail Lite and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://phlymail.com/en/index.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/phlymail/phlymail", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( ! res ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && ">phlyMail Lite<" >< res &&
      '>Passwort vergessen?' >< res && '>Passwort:<' >< res ) {

    req = http_get(item:string(dir,"/frontend/derefer.php?go=",
    "http://",get_host_ip(),dir,"/index.php"), port:port);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "HTTP/1.. 302" && res =~ "Location:.*index.php")
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
