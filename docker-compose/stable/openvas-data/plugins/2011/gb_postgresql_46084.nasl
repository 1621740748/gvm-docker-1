###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL 'intarray' Module 'gettoken()' Buffer Overflow Vulnerability
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103054");
  script_version("2020-01-28T13:26:39+0000");
  script_tag(name:"last_modification", value:"2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2011-02-02 13:26:27 +0100 (Wed, 02 Feb 2011)");
  script_bugtraq_id(46084);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4015");
  script_name("PostgreSQL 'intarray' Module 'gettoken()' Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_lin.nasl", "secpod_postgresql_detect_win.nasl");
  script_mandatory_keys("postgresql/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46084");
  script_xref(name:"URL", value:"http://www.postgresql.org/about/news.1289");

  script_tag(name:"summary", value:"PostgreSQL is prone to a buffer-overflow vulnerability because
  the application fails to perform adequate boundary checks on
  user-supplied data. The issue affects the 'intarray' module.");

  script_tag(name:"impact", value:"An authenticated attacker can leverage this issue to execute arbitrary
  code within the context of the vulnerable application. Failed exploit
  attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"The issue affect versions prior to 8.2.20, 8.3.14, 8.4.7, and 9.0.3.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
loc = infos["location"];

if( version_in_range( version:vers, test_version:"8.2", test_version2:"8.2.19" ) ||
    version_in_range( version:vers, test_version:"8.3", test_version2:"8.3.13" ) ||
    version_in_range( version:vers, test_version:"8.4", test_version2:"8.4.6" )  ||
    version_in_range( version:vers, test_version:"9.0", test_version2:"9.0.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
