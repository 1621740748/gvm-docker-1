###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco ATA 187 Analog Telephone Adapter Unauthorized Access Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140086");
  script_bugtraq_id(57782);
  script_cve_id("CVE-2013-1111");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_version("2020-07-31T08:46:05+0000");

  script_name("Cisco ATA 187 Analog Telephone Adapter Unauthorized Access Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57782");

  script_tag(name:"vuldetect", value:"Try to connect to TCP port 7870 and execute the `id` command.");

  script_tag(name:"insight", value:"The Cisco ATA 187 Analog Telephone Adaptor with firmware 9.2.1.0 and 9.2.3.1
  before ES build 4 does not properly implement access control, which allows remote attackers to execute
  operating-system commands via vectors involving a session on TCP port 7870");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"Cisco ATA-187 is prone to a security-bypass vulnerability because it allows
  attackers to gain unauthorized access to the device.");

  script_tag(name:"affected", value:"An attacker can exploit this issue to view and modify the configuration of an
  affected device, thereby aiding in further attacks.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"2020-07-31 08:46:05 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"creation_date", value:"2016-12-01 14:36:57 +0100 (Thu, 01 Dec 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ata_consolidation.nasl");
  script_mandatory_keys("cisco/ata/detected");
  script_require_ports(7870);

  exit(0);
}

include("telnet_func.inc");

# nb: While the advisory says only ATA 187 is affected we still want to test
# all ATA devices to be sure that no other unknown devices are affected as well.
if( ! get_kb_item( "cisco/ata/detected" ) )
  exit( 0 );

port = 7870;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

telnet_negotiate( socket:soc );

send( socket:soc, data:'id\n');

recv = recv( socket:soc, length:128 );

close( soc );

if( recv =~ "uid=[0-9]+.*gid=[0-9]+" )
{
  report = 'It was possible to execute the `id` command by connection to port `7870` of the remote device.\nResponse:\n' + recv + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
