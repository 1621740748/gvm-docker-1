# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.112742");
  script_version("2021-07-07T02:00:46+0000");
  script_tag(name:"last_modification", value:"2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-05-07 07:46:00 +0000 (Thu, 07 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-07 14:13:00 +0000 (Thu, 07 May 2020)");

  script_cve_id("CVE-2020-11727");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Advanced Order Export For WooCommerce Plugin < 3.1.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woo-order-export-lite/detected");

  script_tag(name:"summary", value:"Advanced Order Export For WooCommerce plugin for WordPress is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows remote attackers to inject arbitrary JavaScript or HTML via the view/settings-form.php woe_post_type parameter.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to perform unauthorized actions in the user's security context.");

  script_tag(name:"affected", value:"WordPress Advanced Order Export For WooCommerce plugin before version 3.1.4.");

  script_tag(name:"solution", value:"Update the plugin to version 3.1.4 or later.");

  script_xref(name:"URL", value:"https://www.themissinglink.com.au/security-advisories-cve-2020-11727");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/woo-order-export-lite/#developers");

  exit(0);
}

CPE = "cpe:/a:algolplus:woo-order-export-lite";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
