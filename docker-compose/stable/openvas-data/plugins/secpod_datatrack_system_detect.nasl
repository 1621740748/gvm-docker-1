###############################################################################
# OpenVAS Vulnerability Test
#
# DataTrack System Detection (HTTP)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902061");
  script_version("2020-12-23T12:06:42+0000");
  script_tag(name:"last_modification", value:"2020-12-23 12:06:42 +0000 (Wed, 23 Dec 2020)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DataTrack System Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 81);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of DataTrack System.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:81);
res = http_get_cache(port:port, item:"/");
if(!res)
  exit(0);

if(!concluded = egrep(string:res, pattern:"(>DataTrack Web Client<|^Server\s*:\s*MagnoWare)", icase:TRUE))
  exit(0);

concluded = chomp(concluded);
version = "unknown";
install = port + "/tcp";

vers = eregmatch(pattern:"Server\s*:\s*MagnoWare/([0-9.]+)", string:res);
if(vers[1]) {
  version = vers[1];
  concluded = vers[0];
}

set_kb_item(name:"www/" + port + "/DataTrack_System", value:version);
set_kb_item(name:"datatrack_system/detected", value:TRUE);

register_and_report_cpe(app:"DataTrack System",
                        ver:version,
                        concluded:concluded,
                        base:"cpe:/a:magnoware:datatrack_system:",
                        expr:"([0-9.]+)",
                        insloc:install,
                        regPort:port,
                        regService:"www");

exit(0);
