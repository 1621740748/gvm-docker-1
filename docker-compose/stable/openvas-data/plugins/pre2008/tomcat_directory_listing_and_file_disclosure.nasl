###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Directory Listing and File disclosure
#
# Authors:
# Bekrar Chaouki - A.D.Consulting <bekrar@adconsulting.fr>
#
# Copyright:
# Copyright (C) 2003 A.D.Consulting
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
###############################################################################

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11438");
  script_version("2021-01-15T14:11:28+0000");
  script_tag(name:"last_modification", value:"2021-01-15 14:11:28 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(6721);
  script_cve_id("CVE-2003-0042");
  script_name("Apache Tomcat Directory Listing and File disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 A.D.Consulting");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_tag(name:"solution", value:"Update Tomcat to version 4.1.18 or later.");

  script_tag(name:"summary", value:"Apache Tomcat (prior to 3.3.1a) is prone to a directory listing and file
  disclosure vulnerability.");

  script_tag(name:"insight", value:"The flaw allows remote attackers to potentially list directories even
  with an index.html or other file present, or obtain unprocessed source code for a JSP file.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

res = http_get_cache( item:"/", port:port );
if( ! res || "Index of /" >< res || "Directory Listing" >< res )
  exit( 0 );

req = http_get( item:"/<REPLACEME>.jsp", port:port );
req = str_replace( string:req, find:"<REPLACEME>", replace:raw_string( 0 ) );
res = http_keepalive_send_recv( port:port, data:req );
if( ! res )
  exit( 0 );

if( "Index of /" >< res || "Directory Listing" >< res ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
