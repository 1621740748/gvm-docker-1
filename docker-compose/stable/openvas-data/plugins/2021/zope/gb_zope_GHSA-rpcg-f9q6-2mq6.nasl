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

CPE = "cpe:/a:zope:zope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146096");
  script_version("2021-06-09T06:36:35+0000");
  script_tag(name:"last_modification", value:"2021-06-09 06:36:35 +0000 (Wed, 09 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-09 06:32:37 +0000 (Wed, 09 Jun 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2021-32674");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zope RCE Vulnerability (GHSA-rpcg-f9q6-2mq6)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zope_detect.nasl");
  script_mandatory_keys("zope/detected");

  script_tag(name:"summary", value:"Zope is prone to a remote code execution (RCE) vulnerability
  via a traversal in TAL expressions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Most Python modules are not available for using in TAL expressions
  that you can add through-the-web, for example in Zope Page Templates. This restriction avoids file
  system access, for example via the 'os' module. But some of the untrusted modules are available
  indirectly through Python modules that are available for direct use.

  By default, you need to have the Manager role to add or edit Zope Page Templates through the web.
  Only sites that allow untrusted users to add/edit Zope Page Templates through the web are at risk.");

  script_tag(name:"affected", value:"Zope prior to version 4.6.1 and 5.2.1.");

  script_tag(name:"solution", value:"Update to version 4.6.1, 5.2.1 or later.");

  script_xref(name:"URL", value:"https://github.com/zopefoundation/Zope/security/advisories/GHSA-rpcg-f9q6-2mq6");

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

if (version_is_less(version: version, test_version: "4.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
