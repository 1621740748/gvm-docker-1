###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: PostgreSQL SSL/TLS Support Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105013");
  script_version("2020-01-28T13:26:39+0000");
  script_tag(name:"last_modification", value:"2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2014-04-25 11:29:22 +0100 (Fri, 25 Apr 2014)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSL/TLS: PostgreSQL SSL/TLS Support Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("postgresql_detect.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("postgresql/detected");

  script_tag(name:"summary", value:"Checks if the remote PostgreSQL server supports SSL/TLS.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/ssl-tcp.html");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"postgresql" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! get_tcp_port_state( port ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

req = raw_string( 0x00, 0x00, 0x00, 0x08,
                  0x04, 0xD2, 0x16, 0x2F );

send( socket:soc, data:req );
recv = recv( socket:soc, length:1 );
close( soc );
if( ! recv )
  exit( 0 );

if( recv == "S" ) {
  set_kb_item( name:"postgres/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"postgres" );
  log_message( port:port, data:"The remote PostgreSQL server supports SSL/TLS." );
}

exit( 0 );
