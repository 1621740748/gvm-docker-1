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
  script_oid("1.3.6.1.4.1.25623.1.0.112599");
  script_version("2020-11-10T11:45:08+0000");
  script_tag(name:"last_modification", value:"2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2019-07-05 13:23:00 +0200 (Fri, 05 Jul 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-12826");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Widget Logic Plugin < 5.10.2 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/widget-logic/detected");

  script_tag(name:"summary", value:"The WordPress plugin Widget Logic is prone to a CSRF vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute PHP code via snippets
  (that are attached to widgets and then evalued to dynamically determine their visibility) by crafting a malicious
  POST request that tricks administrators into adding the code.");
  script_tag(name:"affected", value:"WordPress Widget Logic plugin before version 5.10.2.");
  script_tag(name:"solution", value:"Update to version 5.10.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/widget-logic/#developers");
  script_xref(name:"URL", value:"https://dannewitz.ninja/posts/widget-logic-csrf-to-rce");

  exit(0);
}

CPE = "cpe:/a:wpchef:widget-logic";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.10.2" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.10.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
