###############################################################################
# OpenVAS Vulnerability Test
#
# phpMyAdmin Multiple Security Vulnerabilities - 01 - Dec16 (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108127");
  script_version("2020-11-19T14:17:11+0000");
  script_tag(name:"last_modification", value:"2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-04-10 12:18:02 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2016-9863", "CVE-2016-9862");
  script_name("phpMyAdmin Multiple Security Vulnerabilities - 01 - Dec16 (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - With a very large request to table partitioning function, it is possible to invoke a Denial of Service (DoS) attack.

  - With a crafted login request it is possible to inject BBCode in the login page.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.6.x prior to 4.6.5.");

  script_tag(name:"solution", value:"Update to version 4.6.5 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^4\.6\." ) {
  if( version_is_less( version:vers, test_version:"4.6.5" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"4.6.5" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
