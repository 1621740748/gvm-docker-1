###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Events Manager Plugin < 5.9 XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112284");
  script_version("2021-05-27T06:00:15+0200");
  script_tag(name:"last_modification", value:"2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)");
  script_tag(name:"creation_date", value:"2018-05-16 13:13:00 +0200 (Wed, 16 May 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-10 01:15:00 +0000 (Fri, 10 Jan 2020)");

  script_cve_id("CVE-2018-0576");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Events Manager Plugin < 5.9 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/events-manager/detected");

  script_tag(name:"summary", value:"Events Manager plugin for WordPress is prone to a cross-site scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Events Manager plugin before version 5.9.");

  script_tag(name:"solution", value:"Update to version 5.9 or later.");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN85531148/index.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/events-manager/#developers");

  exit(0);
}

CPE = "cpe:/a:marcus_sykes:events-manager";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "5.9" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
