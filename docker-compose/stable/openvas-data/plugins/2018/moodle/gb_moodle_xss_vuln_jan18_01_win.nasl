###############################################################################
# OpenVAS Vulnerability Test
#
# Moodle 3.x XSS Vulnerability - Jan'18 (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112280");
  script_version("2021-05-21T08:11:46+0000");
  script_tag(name:"last_modification", value:"2021-05-21 08:11:46 +0000 (Fri, 21 May 2021)");
  script_tag(name:"creation_date", value:"2018-05-09 13:39:41 +0200 (Wed, 09 May 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-05 21:27:00 +0000 (Mon, 05 Feb 2018)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-1045");
  script_bugtraq_id(102755);

  script_name("Moodle 3.x XSS Vulnerability - Jan'18 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Moodle is prone to cross-site scripting (XSS) in calendar event name.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It is possible to inject javascript in the event name in the calendar block.
  Normally capability to create events is only given to trusted users (such as teachers).");
  script_tag(name:"affected", value:"Moodle versions 3.3 to 3.3.3, 3.2 to 3.2.6, 3.1 to 3.1.9 and earlier unsupported versions.");
  script_tag(name:"solution", value:"Update to version 3.3.4, 3.2.7 or 3.1.10 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=364384");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( port: port, cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if( version_is_less( version: version, test_version: "3.1.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.10", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.7", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.3.0", test_version2: "3.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.4", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
