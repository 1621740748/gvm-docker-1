###############################################################################
# OpenVAS Vulnerability Test
#
# nginx HTTP Request Remote Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100276");
  script_version("2021-02-01T11:36:44+0000");
  script_tag(name:"last_modification", value:"2021-02-01 11:36:44 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_bugtraq_id(36384);
  script_cve_id("CVE-2009-2629");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("nginx HTTP Request Remote Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36384");
  script_xref(name:"URL", value:"http://nginx.net/CHANGES-0.5");
  script_xref(name:"URL", value:"http://nginx.net/CHANGES-0.6");
  script_xref(name:"URL", value:"http://nginx.net/CHANGES-0.7");
  script_xref(name:"URL", value:"http://nginx.net/CHANGES");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/180065");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"nginx is prone to a buffer-overflow vulnerability
  because the application fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code within the context
  of the affected application. Failed exploit attempts will result in a denial-of-service condition.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "0.5.38") ||
    version_in_range( version: version, test_version: "0.6", test_version2: "0.6.38" ) ||
    version_in_range( version: version, test_version: "0.7", test_version2: "0.7.61" ) ||
    version_in_range( version: version, test_version: "0.8", test_version2: "0.8.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
