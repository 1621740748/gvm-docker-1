###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat AJP Protocol Security Bypass Vulnerability
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

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103242");
  script_version("2021-01-15T14:11:28+0000");
  script_tag(name:"last_modification", value:"2021-01-15 14:11:28 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"creation_date", value:"2011-09-08 12:04:18 +0200 (Thu, 08 Sep 2011)");
  script_bugtraq_id(49353);
  script_cve_id("CVE-2011-3190");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Apache Tomcat AJP Protocol Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49353");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");

  script_tag(name:"impact", value:"Successful exploits will allow attackers to bypass certain security
  restrictions.");

  script_tag(name:"affected", value:"Tomcat 5.5.0 through 5.5.33, Tomcat 6.0.0 through 6.0.33, Tomcat 7.0.0
  through 7.0.20");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"Apache Tomcat is prone to a security-bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.20" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.33" ) ||
    version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.33" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.34/6.0.34/7.0.21", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
