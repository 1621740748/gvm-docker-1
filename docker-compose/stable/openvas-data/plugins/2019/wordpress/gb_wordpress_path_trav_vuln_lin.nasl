# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142032");
  script_version("2020-02-24T10:12:54+0000");
  script_tag(name:"last_modification", value:"2020-02-24 10:12:54 +0000 (Mon, 24 Feb 2020)");
  script_tag(name:"creation_date", value:"2019-02-22 14:19:50 +0700 (Fri, 22 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2019-8943");
  script_bugtraq_id(107089);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress < 5.1 Path Traversal Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"WordPress allows Path Traversal in wp_crop_image(). An attacker (who has
privileges to crop an image) can write the output image to an arbitrary directory via a filename containing two
image extensions and ../ sequences, such as a filename ending with the .jpg?/../../file.jpg substring.");

  script_tag(name:"affected", value:"WordPress version 5.0.3 and prior.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to WordPress version 5.1 or later.");

  script_xref(name:"URL", value:"https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
