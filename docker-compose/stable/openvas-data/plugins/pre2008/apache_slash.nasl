# OpenVAS Vulnerability Test
# Description: Check for Apache Multiple '/' Vulnerability
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
# changes by rd : - script description
#                 - more verbose report
#                 - check for k < 16 in find_index()
#                 - script id
#
# Copyright:
# Copyright (C) 2000 John Lampe <j_lampe@bellsouth.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10440");
  script_version("2021-02-25T13:36:35+0000");
  script_tag(name:"last_modification", value:"2021-02-25 13:36:35 +0000 (Thu, 25 Feb 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1284);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0505");
  script_name("Apache HTTP Server Multiple '/' Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2000 John Lampe <j_lampe@bellsouth.net>");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected", "Host/runs_windows");

  script_tag(name:"solution", value:"Update to the most recent version of Apache HTTP Server.");

  script_tag(name:"summary", value:"Certain versions of Apache HTTP Server for Win32 have a
  bug wherein remote users can list directory entries.");

  script_tag(name:"insight", value:"Specifically, by appending multiple /'s to the HTTP GET
  command, the remote Apache server will list all files and subdirectories within the web
  root (as defined in httpd.conf).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

function find_index(k, port) {

  if(k < 16)
    k = 17;

  for(q = k - 16; q < k; q++) {
    buf = http_get(item:crap(length:q, data:"/"), port:port);
    incoming = http_keepalive_send_recv(port:port, data:buf);
    if (!incoming)
      continue;

    if("Index of /" >< incoming)  {
      report = string(q, " slashes will cause the directory contents to be listed.");
      security_message(port:port, data:report);
      exit(0);
    }
  }
  exit(0);
}

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port))
  exit(0);

res = http_get_cache(item:"/", port:port);
if(!res || "Index of /" >< res)
  exit(0);

for(i=2; i < 512; i=i+16) {
  req = http_get(item:crap(length:i, data:"/"), port:port);
  incoming = http_keepalive_send_recv(port:port, data:req);
  if(!incoming)
    continue;

  if("Forbidden" >< incoming) {
    find_index(k:i, port:port);
  }
}

exit(99);
