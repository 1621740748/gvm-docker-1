###############################################################################
# OpenVAS Vulnerability Test
#
# Emby Media Server Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107098");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-05-02 14:04:20 +0200 (Tue, 02 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Emby Media Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8096);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Emby Media Server.

The script sends a connection request to the server and attempts to detect Emby Media Server and to
extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default: 8096);
url = '/web/login.html';

res = http_get_cache(port: port, item: url);

if ("<title>Emby</title>" >< res && "Energize your media" >< res && "emby-input" >< res)
{
    tmpVer = eregmatch(pattern: "\.js\?v=([0-9.]+)", string: res);
    if(!isnull(tmpVer[1])) {
      version = tmpVer[1];
      set_kb_item(name: "emby_media_server/version", value: version);
    }

    set_kb_item( name:"emby_media_server/installed", value:TRUE );

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:emby:media:");
    if (!cpe)
      cpe = 'cpe:/a:emby:media';

    register_product(cpe: cpe, location: "/", port: port, service: "www");

    log_message( data:build_detection_report(app:"Emby Media Server", version: version, install: "/",
                                             cpe:cpe, concluded: tmpVer[0]),
                 port:port);

    exit( 0 );
}

exit(0);
