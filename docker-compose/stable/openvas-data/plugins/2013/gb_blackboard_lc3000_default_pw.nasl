###############################################################################
# OpenVAS Vulnerability Test
#
# Blackboard LC3000 Laundry Reader Default Telnet Password
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103843");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Blackboard LC3000 Laundry Reader Default Telnet Password");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2013/10/28/290/");

  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-12-02 11:02:55 +0200 (Mon, 02 Dec 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/blackboard/lc3000/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"impact", value:"Attackers can exploit these issues to gain unauthorized access to the
  affected device and perform certain administrative actions.");

  script_tag(name:"vuldetect", value:"Start a telnet session with the default password.");

  script_tag(name:"insight", value:"A user can login to the Telnet service using the default password
  'IPrdr4U'");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"summary", value:"The remote Blackboard LC3000 Laundry Reader is prone to a default
  credentials bypass vulnerability");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port(default:23);
banner = telnet_get_banner(port:port);
if(!banner || 'Blackboard LC3000' >!< banner)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

recv = recv(socket:soc, length:1024);
if("Enter Password" >!< recv)exit(0);

send(socket:soc, data:'IPrdr4U\r\n');

recv = recv(socket:soc, length:1024);
close(soc);

if("showconfig" >< recv && "ipreboot" >< recv) {
  security_message(port:port);
  exit(0);
}

exit(99);
