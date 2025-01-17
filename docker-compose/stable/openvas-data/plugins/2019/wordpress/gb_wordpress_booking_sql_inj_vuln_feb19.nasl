# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112548");
  script_version("2020-08-06T13:39:56+0000");
  script_tag(name:"last_modification", value:"2020-08-06 13:39:56 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-03-28 23:28:11 +0100 (Thu, 28 Mar 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2018-20556");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Booking Calendar Plugin < 8.4.5 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/booking/detected");

  script_tag(name:"summary", value:"The WordPress plugin Booking Calendar is prone to an SQL injection vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to read arbitrary data from the database.");
  script_tag(name:"affected", value:"WordPress Booking Calendar plugin before version 8.4.5.");
  script_tag(name:"solution", value:"Update to version 8.4.5 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/151692/WordPress-Booking-Calendar-8.4.3-SQL-Injection.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/booking/#developers");

  exit(0);
}

CPE = "cpe:/a:wpdevelop:booking";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less(version: version, test_version: "8.4.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.4.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}


exit( 99 );
