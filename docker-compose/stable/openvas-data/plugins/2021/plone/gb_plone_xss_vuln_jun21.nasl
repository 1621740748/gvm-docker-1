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

CPE = "cpe:/a:plone:plone";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146208");
  script_version("2021-07-02T04:12:50+0000");
  script_tag(name:"last_modification", value:"2021-07-02 04:12:50 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-02 04:07:06 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-35959");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plone 5.0.0 <= 5.2.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_plone_detect.nasl");
  script_mandatory_keys("plone/installed");

  script_tag(name:"summary", value:"Plone is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Editors are vulnerable to XSS in the folder contents view, if a
  Contributor has created a folder with a SCRIPT tag in the description field.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  inject arbitrary JavaScript into the site.");

  script_tag(name:"affected", value:"Plone version 5.0.0 through 5.2.4.");

  script_tag(name:"solution", value:"Install hotfix package 1.5 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/06/30/2");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20210518/stored-xss-in-folder-contents");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply hotfix package 1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
