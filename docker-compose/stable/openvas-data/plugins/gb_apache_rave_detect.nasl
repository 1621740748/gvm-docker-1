###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Rave Version Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803179");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-03-14 16:52:17 +0530 (Thu, 14 Mar 2013)");
  script_name("Apache Rave Version Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Apache Rave.

 The script sends a connection request to the server and attempts to
 extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

include("host_details.inc");

port = http_get_port(default:8080);

foreach dir (make_list_unique("/", "/rave", "/portal", "/social", http_cgi_dirs(port:port)))
{

  install = dir;
  if (dir == "/") dir = "";

  url = string(dir, "/login");
  buf = http_get_cache(item:url, port:port);
  if( buf == NULL ) continue;

  if(">RAVE<" >< buf && ">Apache Rave" >< buf)
  {

    vers = string("unknown");

    version = eregmatch(string:buf, pattern:'>Apache Rave ([0-9.]+)',icase:TRUE);
    if(!isnull(version[1])) {
      vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/ApacheRave"),
                value: string(vers," under ",install));
    set_kb_item(name:"ApacheRave/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:apache:rave:");
    if(isnull(cpe))
      cpe = 'cpe:/a:apache:rave';

    register_product(cpe:cpe, location:install, port:port, service:"www");
    log_message(data: build_detection_report(app:"Apache Rave",
                                             version:vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded:version[0]),
                                             port:port);
  }
}

exit(0);
