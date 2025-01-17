# OpenVAS Vulnerability Test
# Description: Extent RBS ISP
#
# Authors:
# Zorgon <zorgon@linuxstart.com>
#
# Copyright:
# Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10521");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1704);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-1036");
  script_name("Extent RBS ISP");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Remove the software or check for updates provided by the vendor.");

  script_tag(name:"summary", value:"The 'Extent RBS ISP 2.5' software is installed. This
  software has a well known security flaw that lets anyone read arbitrary
  files with the privileges of the http daemon (root or nobody).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

res = http_is_cgi_installed_ka(port:port, item:"/newuser");
if(!res)
  exit(0);

url = "/newuser?Image=../../database/rbsserv.mdb";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);
if(!res)
  exit(0);

if("SystemErrorsPerHour" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
