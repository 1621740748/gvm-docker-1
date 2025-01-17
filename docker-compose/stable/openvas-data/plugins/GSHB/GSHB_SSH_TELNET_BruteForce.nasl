###############################################################################
# OpenVAS Vulnerability Test
#
# SSH and Telnet BruteForce attack
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96104");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-09-28 12:16:21 +0200 (Tue, 28 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("IT-Grundschutz: SSH and Telnet BruteForce attack");
  script_add_preference(name:"BruteForce Attacke with Default-Usern and -Passwords", type:"checkbox", value:"no");
  script_category(ACT_ATTACK);
  script_timeout(2400);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "ssh_authorization.nasl");

  script_tag(name:"summary", value:"SSH and Telnet BruteForce attack.");

  exit(0);
}

include("telnet_func.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("default_account.inc");
include("GSHB_BruteForce.inc");

start = script_get_preference("BruteForce Attacke with Default-Usern and -Passwords");
if(start == "no") {
  set_kb_item(name:"GSHB/BRUTEFORCE/SSH", value:"deactivated");
  set_kb_item(name:"GSHB/BRUTEFORCE/TELNET", value:"deactivated");
  exit(0);
}

function check_ssh_account(login, password, port) {

  soc = open_sock_tcp(port);
  if(!soc)
    return -1;

  val = ssh_login(socket:soc, login:login, password:password);
  close(soc);
  if(val == 0)
    return 1;
  else
    return 0;
}

function check_telnet_account(login, password, port) {

  soc = open_sock_tcp(port);
  if(!soc)
    return -1;

  ret = telnet_negotiate(socket:soc, pattern:"(ogin:|asscode:|assword:)");
  if(strlen(ret)) {

    if(stridx(ret, "sername:") != -1 || stridx(ret, "ogin:") != -1) {
      send(socket:soc, data:string(login, "\r\n"));
      ret = recv_until(socket:soc, pattern:"(assword:|asscode:)");
    }

    if(stridx(ret, "assword:") == -1 && stridx(ret, "asscode:") == -1 ) {
      close(soc);
      return 0;
    }

    send(socket:soc, data:string(password, "\r\n"));
    r = recv(socket:soc, length:4096);
    send(socket:soc, data:string("ping\r\n"));
    r = recv_until(socket:soc, pattern:"(assword:|asscode:|ogin:|% Bad password)");
    close(soc);

    if(!r)
      return 1;

    return 0;
  }
}

ssh_ports = ssh_get_ports(default_port_list:make_list(22), ignore_unscanned:TRUE);
foreach ssh_port(ssh_ports) {

  for(i = 0; i < max_index(BruteForcePWList); i++) {
    Lst = split(BruteForcePWList[i], sep:'|', keep:FALSE);
    sshbrute = check_ssh_account(login:Lst[0], password:Lst[1], port:ssh_port);
    if(sshbrute) {
      i = 999999;
      ssh_result = "Username: " + Lst[0] + ", Password: " + Lst[1];
    } else if(sshbrute == -1) {
      break;
    } else {
      ssh_result = "ok";
    }
  }
}

if(sshbrute == -1 && !ssh_result)
  ssh_result = "nossh";

telnet_ports = telnet_get_ports(default_port_list:make_list(23), ignore_unscanned:TRUE);
foreach telnet_port(telnet_ports) {

  for(i = 0; i < max_index(BruteForcePWList); i++) {
    Lst = split(BruteForcePWList[i], sep:'|', keep:FALSE);
    if(Lst[0] == "")
      continue;

    telnetbrute = check_telnet_account(login:Lst[0], password:Lst[1], port:telnet_port);
    if(telnetbrute) {
      i = 999999;
      telnet_result = "Username: " + Lst[0] + ", Password: " + Lst[1];
    } else if(telnetbrute == -1) {
      break;
    } else {
      telnet_result = "ok";
    }
  }
}

if(telnet_port == -1 && !telnet_result)
  telnet_result = "notelnet";

set_kb_item(name:"GSHB/BRUTEFORCE/SSH", value:ssh_result);
set_kb_item(name:"GSHB/BRUTEFORCE/TELNET", value:telnet_result);

exit(0);
