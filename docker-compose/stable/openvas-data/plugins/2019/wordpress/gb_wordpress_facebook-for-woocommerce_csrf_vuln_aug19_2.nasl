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
  script_oid("1.3.6.1.4.1.25623.1.0.113505");
  script_version("2020-11-10T11:45:08+0000");
  script_tag(name:"last_modification", value:"2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2019-09-11 10:46:53 +0000 (Wed, 11 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15841");

  script_name("WordPress Facebook for WooCommerce Plugin < 1.9.15 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/facebook-for-woocommerce/detected");

  script_tag(name:"summary", value:"The WordPress plugin Facebook for WooCommerce is prone to a cross-site request forgery (CSRF) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is exploitable via ajax_woo_infobanner_post_click,
  ajax_woo_infobanner_post_xout and ajax_fb_toggle_visibility.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to perform actions
  in the context of another user.");
  script_tag(name:"affected", value:"WordPress Facebook for WooCommerce plugin through version 1.9.14.");
  script_tag(name:"solution", value:"Update to version 1.9.15.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/facebook-for-woocommerce/#developers");

  exit(0);
}

CPE = "cpe:/a:facebook:facebook-for-woocommerce";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.9.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.9.15", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
