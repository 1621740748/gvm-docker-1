###############################################################################
# OpenVAS Vulnerability Test
#
# Octopus Deploy XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:octopus:octopus_deploy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140518");
  script_version("2020-08-26T13:14:57+0000");
  script_tag(name:"last_modification", value:"2020-08-26 13:14:57 +0000 (Wed, 26 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-11-21 13:29:51 +0700 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2017-16801");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Octopus Deploy XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_octopus_deploy_detect.nasl");
  script_mandatory_keys("octopus/octopus_deploy/detected");

  script_tag(name:"summary", value:"Cross-site scripting (XSS) vulnerability in Octopus Deploy allows remote
authenticated users to inject arbitrary web script or HTML via the Step Template Name parameter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Octopus Deploy version 3.7.0 until 3.17.13.");

  script_tag(name:"solution", value:"Update to version 3.17.14 or later.");

  script_xref(name:"URL", value:"https://github.com/OctopusDeploy/Issues/issues/3915");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.7.0", test_version2: "3.17.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.17.14");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
