# OpenVAS Vulnerability Test
# Description: NiteServer FTP directory traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11466");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_cve_id("CVE-2003-1349");
  script_bugtraq_id(6648);
  script_name("NiteServer FTP directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/login");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"solution", value:"Upgrade your FTP server.");

  script_tag(name:"summary", value:"The remote FTP server allows anybody to switch to the
  root directory and read potentially sensitive files.");

  script_tag(name:"affected", value:"Known affected products are:

  NITE ftp-server version 1.83

  121 WAM! Server 1.0.4.0");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);

soc = open_sock_tcp(port);
if (! soc) exit(0);

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

if (! ftp_authenticate(socket:soc, user: login, pass: pass)) {
  ftp_close(socket:soc);
  exit(0);
}

send(socket: soc, data: 'CWD\r\n');
r = ftp_recv_line(socket: soc);
send(socket: soc, data: 'PWD\r\n');
r = ftp_recv_line(socket: soc);
matches = egrep(string:r, pattern:'^[0-9]+ *"([^"]+)"');
if (matches) {
  foreach match (matches) {
    match = chomp(match);
    v = eregmatch(string:match, pattern:'^[0-9]+ *"([^"]+)"');
    if (! isnull(v)) {
      cur1 = v[1];
      break;
    }
  }
}

# Loop on vulnerable patterns
dirs = make_list("\..\..\..\..\..", "/../");
foreach d (dirs)
{
  send(socket: soc, data: 'CWD ' + d + '\r\n');

  r = ftp_recv_line(socket: soc);
  send(socket: soc, data: 'PWD\r\n');
  r = ftp_recv_line(socket: soc);
  matches = egrep(string:r, pattern:'^[0-9]+ *"([^"]+)"');
  if (matches) {
    foreach match (matches) {
      match = chomp(match);
      v = eregmatch(string:match, pattern:'^[0-9]+ *"([^"]+)"');
      if (! isnull(v)) {
        cur2 = v[1];
        break;
      }
    }
  }

  if (cur1 && cur2)
  {
    if (cur1 != cur2)
      security_message(port);
    ftp_close(socket: soc);
    exit(0);
  }

  p = ftp_pasv(socket:soc);
  if(p)
  {
    soc2 = open_sock_tcp(p, transport:get_port_transport(port));
    if(soc2)
    {
      send(socket:soc, data: 'LIST\r\n');
      r = ftp_recv_listing(socket:soc2);
      r = tolower(r);
      r2 = ftp_recv_line(socket: soc);
      close(soc2);
      if ("autoexec.bat" >< r || "boot.ini" >< r || "config.sys" >< r)
      {
        security_message(port);
        break;
      }
    }
  }
}

ftp_close(socket: soc);
