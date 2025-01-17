###############################################################################
# OpenVAS Vulnerability Test
#
# Weborf Webserver Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801223");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Weborf Webserver Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Weborf/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This script finds the running Weborf Webserver version.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Weborf Webserver Version Detection";

port = http_get_port(default:8080);
banner = http_get_remote_headers(port:port);

if("Server: Weborf" >< banner)
{
  ver = eregmatch(pattern:"Weborf/([0-9.]+)",string:banner);

  if(!ver[0]) {
    url = string("/lhlkjlkjkj-",rand(),".html");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if(buf == NULL)exit(0);

    ver = eregmatch(pattern:"Generated by Weborf/([0-9.]+)", string:buf);

  }

  if(ver[1] != NULL)
  {
    set_kb_item(name:"weborf/detected", value:TRUE);
    set_kb_item(name:"www/" + port + "/Weborf", value:ver[1]);
    log_message(data:"Weborf  Webserver version " + ver[1] +
                       " was detected on the host", port:port);

    cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:galileo_students:team_weborf:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
