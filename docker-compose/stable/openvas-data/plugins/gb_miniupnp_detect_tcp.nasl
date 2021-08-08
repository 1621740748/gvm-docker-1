# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108017");
  script_version("2021-04-14T13:21:59+0000");
  script_tag(name:"last_modification", value:"2021-04-14 13:21:59 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-11-09 16:37:33 +0100 (Wed, 09 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("MiniUPnP Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 5000);
  script_mandatory_keys("miniupnp/banner");

  script_xref(name:"URL", value:"http://miniupnp.free.fr/");

  script_tag(name:"summary", value:"TCP based detection of MiniUPnP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:5000 );
if( ! banner = http_get_remote_headers( port:port ) )
  exit( 0 );

if( concl = egrep( string:banner, pattern:"miniupnp", icase:TRUE ) ) {

  concl = chomp( concl );
  version = "unknown";

  vers = eregmatch( pattern:"miniupnpd/([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    concl = vers[0];
  }

  set_kb_item( name:"miniupnp/detected", value:TRUE );
  set_kb_item( name:"miniupnp/tcp/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:miniupnp_project:miniupnpd:" );
  if( ! cpe )
    cpe = "cpe:/a:miniupnp_project:miniupnpd";

  register_product( cpe:cpe, location:"/", port:port, service:"www" );

  log_message( data:build_detection_report( app:"MiniUPnP",
                                            version:version,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:concl ),
                                            port:port );
}

exit( 0 );