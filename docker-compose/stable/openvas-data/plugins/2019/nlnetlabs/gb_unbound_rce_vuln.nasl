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

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143176");
  script_version("2019-12-18T09:57:42+0000");
  script_tag(name:"last_modification", value:"2019-12-18 09:57:42 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-26 04:07:53 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-18934");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver 1.6.4 - 1.9.4 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to a remote code execution vulnerability under
  certain conditions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unbound contains a vulnerability that can cause shell code execution after
  receiving a specially crafted answer. This issue can only be triggered if unbound was compiled with
  '--enable-ipsecmod' support, and ipsecmod is enabled and used in the configuration.");

  script_tag(name:"affected", value:"Ubound DNS Resolver versions 1.6.4 - 1.9.4.");

  script_tag(name:"solution", value:"Update to version 1.9.5 or later or apply the provided patch.");

  script_xref(name:"URL", value:"https://www.nlnetlabs.nl/downloads/unbound/CVE-2019-18934.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_in_range(version: version, test_version: "1.6.4", test_version2: "1.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.5");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
