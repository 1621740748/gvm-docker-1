# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146108");
  script_version("2021-06-16T12:55:49+0000");
  script_tag(name:"last_modification", value:"2021-06-16 12:55:49 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-11 04:32:53 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-33829");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CKEditor 4.0 < 4.16.1 XSS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ckeditor/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"CKEditor is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An XSS vulnerability in the HTML Data Processor in CKEditor
  allows remote attackers to inject executable JavaScript code through a crafted comment because
  --!> is mishandled.");

  script_tag(name:"affected", value:"CKEditor version 4.0 through 4.16.0.");

  script_tag(name:"solution", value:"Update to version 4.16.1 or later");

  script_xref(name:"URL", value:"https://ckeditor.com/blog/ckeditor-4.16.1-with-accessibility-enhancements/#improvements-for-comments-in-html-parser");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version:"4.0", test_version2: "4.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version:"4.16.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);