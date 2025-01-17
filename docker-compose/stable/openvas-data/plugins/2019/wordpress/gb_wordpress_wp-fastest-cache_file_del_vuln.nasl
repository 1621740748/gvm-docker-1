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
  script_oid("1.3.6.1.4.1.25623.1.0.142690");
  script_version("2020-08-06T13:39:56+0000");
  script_tag(name:"last_modification", value:"2020-08-06 13:39:56 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-08-01 07:53:38 +0000 (Thu, 01 Aug 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2019-6726");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Fastest Cache Plugin < 0.8.9.1 File Deletion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-fastest-cache/detected");

  script_tag(name:"summary", value:"The WordPress Fastest Cache plugin is prone to a file deletion vulnerability.");

  script_tag(name:"insight", value:"The WP Fastest Cache plugin for WordPress allows remote attackers to delete
  arbitrary files because wp_postratings_clear_fastest_cache and rm_folder_recursively in wpFastestCache.php
  mishandle ../ in an HTTP Referer header.");

  script_tag(name:"affected", value:"WordPress Fastest Cache plugin version 0.8.9.0 and prior.");

  script_tag(name:"solution", value:"Update to version 0.8.9.1 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/152042");
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

if ( version_is_less( version: version, test_version: "0.8.9.1" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.8.9.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );