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

CPE = "cpe:/a:opencast:opencast";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112906");
  script_version("2021-06-28T07:09:08+0000");
  script_tag(name:"last_modification", value:"2021-06-28 07:09:08 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 07:51:11 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2021-32623");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenCast < 9.6 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"OpenCast is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Opencast is vulnerable to a so called billion laughs attack,
  which allows an attacker to easily execute a (seemingly permanent) denial of service attack,
  essentially taking down Opencast using a single HTTP request. To exploit this, users need to
  have ingest privileges, limiting the group of potential attackers.");

  script_tag(name:"impact", value:"Successful exploitation will lead to a denial of service,
  affecting the whole application.");

  script_tag(name:"affected", value:"OpenCast prior to version 9.6.");

  script_tag(name:"solution", value:"Update to version 9.6 or later.");

  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-9gwx-9cwp-5c2m");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "9.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
