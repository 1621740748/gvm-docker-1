# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113472");
  script_version("2020-11-10T11:45:08+0000");
  script_tag(name:"last_modification", value:"2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2019-08-27 12:38:25 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-9316");

  script_name("WordPress WP Fastest Cache Plugin < 0.8.4.9 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-fastest-cache/detected");

  script_tag(name:"summary", value:"The WordPress plugin WP Fastest Cache is prone to an SQL injection vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists in wp-admin/admin-ajax.php?action=wpfc_wppolls_ajax_request
  via the poll_id parameter.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read and modify data on the database
  and maybe even execute code on the target machine.");
  script_tag(name:"affected", value:"WordPress WP Fastest Cache plugin through version 0.8.4.8.");
  script_tag(name:"solution", value:"Update to version 0.8.4.9 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38678");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-fastest-cache/#developers");

  exit(0);
}

CPE = "cpe:/a:emrevona:wp-fastest-cache";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "0.8.4.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.8.4.9", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
