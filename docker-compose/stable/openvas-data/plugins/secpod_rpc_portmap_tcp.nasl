###############################################################################
# OpenVAS Vulnerability Test
#
# RPC Portmapper Service Detection (TCP)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108090");
  script_version("2021-04-14T09:28:27+0000");
  script_tag(name:"last_modification", value:"2021-04-14 09:28:27 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RPC Portmapper Service Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_require_ports(111, 121, 530, 593);

  script_tag(name:"summary", value:"TCP based detection of a RPC portmapper service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("rpc.inc");
include("byte_func.inc");

RPC_PROG = 100000;

foreach p( make_list( 111, 121, 530, 593 ) ) {

  if( ! get_tcp_port_state( p ) )
    continue;

  port = rpc_get_port( program:RPC_PROG, protocol:IPPROTO_TCP, portmap:p );
  if( ! port )
    continue;

  replace_kb_item( name:"rpc/portmap", value:p );
  set_kb_item( name:"rpc/portmap/tcp/detected", value:TRUE );
  set_kb_item( name:"rpc/portmap/tcp_or_udp/detected", value:TRUE );
  service_register( port:p, proto:"rpc-portmap" );
  log_message( port:p, data:"A RPC portmapper service is running on this port." );
}

exit( 0 );
