# OpenVAS Vulnerability Test
# Description: SysV /bin/login buffer overflow (telnet)
#
# Authors:
# Renaud Deraison <deraison@nessus.org>
#
# Copyright:
# Copyright (C) 2008 Renaud Deraison
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# Sun's patch makes /bin/login exits when it receives too many arguments,
# hence making the detection of the flaw difficult. Our logic is the
# following :
#
# Username: "vt" -> should not crash
# Username: "vt A=B..... x 61"  -> should not crash
# Username: "vt A=B..... x 100" -> should crash

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80049");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_xref(name:"IAVA", value:"2001-a-0014");
  script_bugtraq_id(3681, 7481);
  script_cve_id("CVE-2001-0797");
  script_xref(name:"IAVA", value:"2002-A-0004");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SysV /bin/login buffer overflow (telnet)");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2008 Renaud Deraison");
  script_family("Gain a shell remotely");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"solution", value:"Contact your vendor for a patch (or read the CERT advisory)");

  script_tag(name:"summary", value:"The remote /bin/login seems to crash when it receives too many environment
  variables.");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain a root shell on this system.");

  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2001-34.html");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

vt_strings = get_vt_strings();
port = telnet_get_port(default:23);

function login(env, try)
{
  local_var i, soc, r, buffer;

  # if (try <= 0) try = 1;
  for (i = 0; i < try; i ++)
  {
    sleep(i);
    soc = open_sock_tcp(port);
    if (soc) break;
  }

  if (soc)
  {
    buffer = telnet_negotiate(socket:soc);
    send(socket:soc, data:string(vt_strings["lowercase"], " ", env, "\r\n"));
    r = recv(socket:soc, length:4096);
    close(soc);
    if("word:" >< r)
    {
      return(1);
    }
  }
  return(0);
}

if(login(env:"", try: 1))
{
 my_env = crap(data:"A=B ", length:244);
 res = login(env:my_env);
 if(res)
 {
  my_env = crap(data:"A=B ", length:400);
  res = login(env:my_env, try: 4);
  if(!res)security_message(port);
 }
}
