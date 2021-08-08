###############################################################################
# OpenVAS Vulnerability Test
#
# Nagios-statd Daemon Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100187");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-12-16T08:01:12+0000");
  script_tag(name:"last_modification", value:"2020-12-16 08:01:12 +0000 (Wed, 16 Dec 2020)");
  script_tag(name:"creation_date", value:"2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Nagios-statd Daemon Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/nagios-statd", 1040);

  script_tag(name:"solution", value:"Limit incoming traffic to this port.");

  script_tag(name:"summary", value:"Nagios-statd Daemon is running at this port.

  Nagios-statd (nagios-statd Daemon) is the daemon program for
  nagios-stat. These programs together comprise a systems monitoring
  tool for various platforms. It is designed to be integrated with the
  Nagios monitoring tool, although this is not a requirement.

  Nagios-statd is the daemon that listens for connections from
  clients. It forks off a new daemon for each incoming connection.
  The forked daemon executes a series of typical UNIX commands and
  returns those commands standard output to the client.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("port_service_func.inc");

port = service_get_port(default:1040, proto:"nagios-statd");

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("version\r\n");
send(socket:soc, data:req);
while (data = recv_line(socket:soc, length:100)) {
  ret += data;
}

close(soc);

if("nagios-statd" >< ret) {

  vers = string("unknown");
  version = eregmatch(pattern:"^nagios-statd ([0-9.]+)$", string:ret);

  if(!isnull(version[1]))
    vers = version[1];

  set_kb_item(name:"nagios_statd/" + port + "/Version", value:vers);
  service_register(port:port, ipproto:"tcp", proto:"nagios-statd");

  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:nagios:nagios:");
  if(!isnull(cpe))
    register_host_detail(name:"App", value:cpe);

  tests = make_list("uptime", "disk");

  foreach do (tests) {

    soc = open_sock_tcp(port);
    if(!soc)
      continue;

    req = string(do, "\r\n");
    send(socket:soc, data:req);

    result += string(do,":\n");

    while (data = recv_line(socket:soc, length:100)) {
      result += data;
    }

    result += string("\n");
    close(soc);
  }

  if(strlen(result)) {
    info = string("Here are a few Information from the nagios-statd daemon received by the scanner:\n\n");
    info += result;
  }

  log_message(port:port, data:info);
  exit(0);
}

exit(0);
