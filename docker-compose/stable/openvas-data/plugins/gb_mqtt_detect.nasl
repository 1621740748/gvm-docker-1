###############################################################################
# OpenVAS Vulnerability Test
#
# MQTT Detection
#
# Authors:
# Michael Meyer
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140166");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-02-17 16:05:55 +0100 (Fri, 17 Feb 2017)");

  script_name("MQTT Broker Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 8883, 1883);

  script_tag(name:"summary", value:"A MQTT Broker is running at this port.");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("byte_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = unknownservice_get_port( default:1883 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

# http://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html

vt_strings = get_vt_strings();
client_id     = vt_strings["default"];
protocol_name = 'MQTT';

len           = mkbyte( strlen( client_id ) + strlen( protocol_name ) + 8 );
client_id_len = mkword( strlen( client_id ) );
proto_len     = mkword( strlen( protocol_name ) );

req = raw_string( 0x10,             # connect command
                  len,              # msg len
                  proto_len ) +     # protocol name len
                  protocol_name +   # protocol name
      raw_string( 0x04,             # version
                  0x02,             # connect flags
                  mkword( 1 ),      # keep alive 1
                  client_id_len ) + # client_id len
                  client_id;

send( socket:soc, data:req );
recv = recv( socket:soc, length:4 );

if( strlen( recv ) != 4 || recv[0] != '\x20' ) { # Connect ACK
  close( soc );
  exit( 0 );
}

len = ord( recv[1] );
if( ( len + 2 ) != strlen( recv ) ) {
  close( soc );
  exit( 0 );
}

ret_code = getword( blob:recv, pos:2 );
# 0x00    Connection Accepted
# 0x01    Connection Refused: unacceptable protocol version
# 0x02    Connection Refused: identifier rejected
# 0x03    Connection Refused: server unavailable
# 0x04    Connection Refused: bad user name or password
# 0x05    Connection Refused: not authorized
set_kb_item( name:"mqtt/connect_ret_code", value:string( ret_code ) );

if( ret_code == '0' ) {
  set_kb_item( name:"mqtt/no_user_pass", value:TRUE );

  req = raw_string( 0x82,                  # Subscribe request
                    0x18,                  # Message length
                    0x00, 0x01,            # Message identifier
                    0x00, 0x13,            # Topic length
                    "$SYS/broker/version",
                    0x00 );                # QoS

  send( socket:soc, data:req );
  recv = recv( socket:soc, length:5 );

  if( recv[0] == '\x90' ) {
    recv = recv( socket:soc, length:128 );

    if( "$SYS/broker/version" >< recv ) {
      vers = split( recv, sep:"broker/version", keep:FALSE );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        set_kb_item( name:"mqtt/" + port + "/server_version", value:version );
        extra += "Version: " + version;
      }
    }
  }
}

close( soc );

report = "A MQTT Broker is running at this port.";

service_register( port:port, proto:"mqtt", message:report );

if( extra )
  report += '\n\nThe following information was extracted:\n\n' + extra;

log_message( port:port, data:report );

exit( 0 );
